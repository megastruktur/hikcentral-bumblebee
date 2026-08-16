"""Live streaming from HikCentral VTDU (rtsp://…/hikvision://… Authenty).

Protocol (reverse-engineered from libStreamClient.so of the official
HikCentral Pro mobile client, 2026-08; see hik_recon/STREAMING-PROTOCOL.md):

1. ``CommonUrl`` API returns the stream URL, VSM token and device creds.
2. RTSP over TCP (port 554) with a proprietary ``Authenty`` handshake::

       OPTIONS <url>                       (User-Agent: StreamClient,
                                          Ability: supportNoLineBreak)
       DESCRIBE <url> + Sep: CIPHER_SUITES="0" + Upgrade: StreamSystem4.1
         → 401 + WWW-Authenticate: SEP CIPHER_SUITE="0", RAND="<b64>"
                PKD: <RSA public key PEM>
       rand_raw16 = b64decode(RAND)
       iv16  = os.urandom(16)
       key32 = os.urandom(16) + rand_raw16          # challenge-mixed!
       DESCRIBE <url> +
         Authorization: SEP DATA="<b64(AES(rand_raw16:user:pass))>"
         Key: <b64(RSA(iv16 + ":" + key32))>
         Identification: <b64(AES(b64-token-string))>
         → 200 + SDP
       SETUP <url>/trackID=1  (RTP/AVP/TCP interleaved 0-1)
       PLAY                      → RTP media on channel 0

   AES-256-CBC, zero-padded payload to roundup16(len+1).

3. Media: interleaved frames ``$<ch><len16><RTP>``; channel 0 / PT 96 is
   raw H.264 in RTP payload format (FU-A fragments, single NALs, STAP-A)
   without any container.  PT 112 frames are Hik-private and skipped.

Public API:

- :class:`StreamInfo` — parsed ``CommonUrl`` response
- :class:`H264RtpDepacketizer` — RTP-payload → Annex-B NAL units
- :class:`AuthentyStreamClient` — blocking live-stream reader
- :func:`capture_h264` — grab N seconds of Annex-B H.264
- :func:`snapshot_jpeg` — grab one JPEG frame via ffmpeg
"""

from __future__ import annotations

import base64
import os
import re
import socket
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Self

__all__ = [
    "AuthentyStreamClient",
    "H264RtpDepacketizer",
    "StreamError",
    "StreamInfo",
    "capture_h264",
    "snapshot_jpeg",
]

_RTSP_PORT = 554
_USER_AGENT = "StreamClient"
_READ_CHUNK = 65536


class StreamError(Exception):
    """Raised when the Authenty handshake or media transfer fails."""


# ---------------------------------------------------------------------------
# CommonUrl parsing
# ---------------------------------------------------------------------------


@dataclass
class StreamInfo:
    """Everything needed to start a live stream for one camera."""

    url: str  # rtsp://host:554/hikvision://…
    username: str
    password: str
    token_b64: str  # base64 string of the VSM token (NOT decoded!)

    @classmethod
    def from_common_url(cls, common: dict, server_host: str = "") -> StreamInfo:
        """Build from the parsed ``commonUrl`` dict of a CommonUrl response.

        ``[sms:preview]rtsp://…`` URLs pass through; ``[sdk:preview]`` direct
        URLs (``ip/port/ch:st:link``) are rewritten to the VTDU form
        ``rtsp://<server_host>:554/hikvision://ip:port:ch:st`` — the VTDU
        proxies direct cameras exactly like NVR channels.
        """
        raw = str(common.get("url", ""))
        prefix = raw.split("]", 1)[0] + "]" if "]" in raw else ""
        url = raw.split("]", 1)[1] if "]" in raw else raw
        if prefix.startswith("[sdk:") and server_host:
            parts = url.split("/")
            if len(parts) >= 3:
                url = f"rtsp://{server_host}:554/hikvision://{parts[0]}:{parts[1]}:{parts[2]}"
        token = common.get("SMSToken", {}).get("Token", "")
        if not url or not token:
            raise StreamError("CommonUrl response lacks url or SMSToken")
        return cls(
            url=url,
            username=str(common.get("UserName", "") or ""),
            password=str(common.get("PassWord", "") or ""),
            token_b64=str(token),
        )

    @property
    def host(self) -> str:
        m = re.match(r"rtsp://([^:/]+)", self.url)
        if not m:
            raise StreamError(f"Malformed stream URL: {self.url!r}")
        return m.group(1)


def parse_common_url(xml_text: str) -> StreamInfo:
    """Parse a CommonUrl ResponseStatus XML body into StreamInfo."""
    root = ET.fromstring(xml_text)
    common = root.find(".//commonUrl")
    if common is None:
        raise StreamError("No commonUrl element in CommonUrl response")
    url_el = common.find("url")
    token_el = common.find(".//SMSToken/Token")
    user_el = common.find("UserName")
    pass_el = common.find("PassWord")
    if url_el is None or url_el.text is None:
        raise StreamError("No url in CommonUrl response")
    url = url_el.text.split("]", 1)[1] if "]" in url_el.text else url_el.text
    if token_el is None or token_el.text is None:
        raise StreamError("No SMSToken in CommonUrl response")
    return StreamInfo(
        url=url,
        username=(user_el.text if user_el is not None and user_el.text else "") or "",
        password=(pass_el.text if pass_el is not None and pass_el.text else "") or "",
        token_b64=token_el.text,
    )


# ---------------------------------------------------------------------------
# RTP H.264 depacketization (RFC 6180)
# ---------------------------------------------------------------------------


class H264RtpDepacketizer:
    """Turn RTP H.264 payloads (PT 96) into Annex-B NAL units.

    Handles single NAL units (types 1–23), STAP-A (24) and FU-A (28).
    STAP-B/MTU-B (25/26) and FU-B (29) are not used by Hik streams.
    """

    _START_CODE = b"\x00\x00\x00\x01"

    def __init__(self) -> None:
        self._fu_buf: bytearray | None = None

    def feed(self, payload: bytes) -> list[bytes]:
        """Feed one RTP payload, return zero or more complete Annex-B NALs."""
        if not payload:
            return []
        nal_type = payload[0] & 0x1F
        if 1 <= nal_type <= 23:
            return [self._START_CODE + payload]
        if nal_type == 24:  # STAP-A
            out: list[bytes] = []
            off = 1
            while off + 2 <= len(payload):
                size = struct.unpack(">H", payload[off : off + 2])[0]
                if off + 2 + size > len(payload):
                    break
                out.append(self._START_CODE + payload[off + 2 : off + 2 + size])
                off += 2 + size
            return out
        if nal_type == 28:  # FU-A
            if len(payload) < 2:
                return []
            start = bool(payload[1] & 0x80)
            end = bool(payload[1] & 0x40)
            if start:
                nal_header = bytes([(payload[0] & 0xE0) | (payload[1] & 0x1F)])
                self._fu_buf = bytearray(nal_header) + payload[2:]
            elif self._fu_buf is not None:
                self._fu_buf += payload[2:]
            if end and self._fu_buf is not None:
                nal = bytes(self._fu_buf)
                self._fu_buf = None
                return [self._START_CODE + nal]
            return []
        # 0 (unspecified), 25/26/27/29 — skip
        return []

    def flush(self) -> list[bytes]:
        """Drop any incomplete FU-A assembly."""
        self._fu_buf = None
        return []


# ---------------------------------------------------------------------------
# Authenty RTSP client
# ---------------------------------------------------------------------------


def _aes_enc(data: bytes, key32: bytes, iv16: bytes) -> bytes:
    """EncryptAndBase64Enc: zero-pad to roundup16(len+1), AES-256-CBC, b64."""
    from Crypto.Cipher import AES  # local import: keeps module import light

    n = ((len(data) + 1 + 15) // 16) * 16
    buf = data + b"\x00" * (n - len(data))
    ct = AES.new(key32, AES.MODE_CBC, iv16).encrypt(buf)
    return base64.b64encode(ct)


class AuthentyStreamClient:
    """Blocking live-stream client speaking the HikCentral Authenty protocol.

    Usage::

        with AuthentyStreamClient(info) as cli:
            cli.play()
            for chunk in cli.h264_chunks(max_seconds=5):
                sink.write(chunk)

    All methods are blocking; call from a thread/executor.
    """

    def __init__(self, info: StreamInfo, timeout: float = 10.0) -> None:
        self._info = info
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""
        self._session: str | None = None
        self._depak = H264RtpDepacketizer()
        self._cseq = 10_000

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- low-level RTSP ----------------------------------------------------

    def _recv_until(self, marker: bytes) -> bytes:
        assert self._sock is not None
        data = self._buf
        while marker not in data:
            chunk = self._sock.recv(_READ_CHUNK)
            if not chunk:
                raise StreamError("RTSP server closed connection")
            data += chunk
        head, _, self._buf = data.partition(marker)
        return head

    def _read_sdp(self) -> tuple[str, str]:
        """Read response head + body honouring Content-Length."""
        assert self._sock is not None
        head = self._recv_until(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":", 1)[1])
        body = self._buf[:clen]
        self._buf = self._buf[clen:]
        deadline = time.monotonic() + self._timeout
        while len(body) < clen:
            if time.monotonic() > deadline:
                raise StreamError("Timeout reading SDP body")
            chunk = self._sock.recv(_READ_CHUNK)
            if not chunk:
                break
            body += chunk
        return head.decode("utf-8", "replace"), body.decode("utf-8", "replace")

    def _request(self, req: str) -> tuple[str, str]:
        assert self._sock is not None
        self._sock.sendall(req.encode())
        head, body = self._read_sdp()
        status = head.split("\r\n", 1)[0]
        if " 200 " not in status:
            raise StreamError(f"RTSP error: {status}")
        return head, body

    @staticmethod
    def _status_of(head: str) -> int:
        try:
            return int(head.split(" ", 2)[1])
        except (IndexError, ValueError):
            return 0

    # -- protocol steps -----------------------------------------------------

    def connect(self) -> None:
        """TCP connect + OPTIONS."""
        self._sock = socket.create_connection(
            (self._info.host, _RTSP_PORT), timeout=self._timeout
        )
        self._sock.settimeout(self._timeout)
        self._cseq += 1
        self._request(
            f"OPTIONS {self._info.url} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Ability: supportNoLineBreak\r\n\r\n"
        )

    def describe_with_challenge(self) -> tuple[bytes, object]:
        """DESCRIBE without auth → expect 401 with RAND + PKD.

        Returns (rand_raw16, rsa_public_key_object).
        """
        from Crypto.PublicKey import RSA

        self._cseq += 1
        assert self._sock is not None
        self._sock.sendall(
            f"DESCRIBE {self._info.url} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            "Accept: application/sdp\r\n"
            'Sep: CIPHER_SUITES="0"\r\n'
            f"User-Agent: {_USER_AGENT}\r\n"
            "Upgrade: StreamSystem4.1\r\n\r\n".encode()
        )
        head = self._recv_until(b"\r\n\r\n")
        head_text = head.decode("utf-8", "replace")
        if self._status_of(head_text) != 401:
            raise StreamError(f"Expected 401 challenge, got: {head_text.splitlines()[0]}")
        # PKD header spans multiple lines until the empty line
        m = re.search(
            r'RAND="([^"]+)"', head_text
        )
        p = re.search(
            r"PKD:\s*(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)",
            head_text,
            re.DOTALL,
        )
        if not m or not p:
            raise StreamError("401 without RAND/PKD challenge")
        rand_raw = base64.b64decode(m.group(1))
        pubkey = RSA.import_key(p.group(1))
        return rand_raw, pubkey

    def describe_authed(self) -> str:
        """Full Authenty DESCRIBE (challenge + 3 crypto headers) → SDP."""
        from Crypto.Cipher import PKCS1_v1_5

        rand_raw, pubkey = self.describe_with_challenge()
        iv16 = os.urandom(16)
        key32 = os.urandom(16) + rand_raw
        sep_data = _aes_enc(
            rand_raw
            + b":"
            + self._info.username.encode()
            + b":"
            + self._info.password.encode(),
            key32,
            iv16,
        )
        ident = _aes_enc(self._info.token_b64.encode(), key32, iv16)
        key_hdr = base64.b64encode(
            PKCS1_v1_5.new(pubkey).encrypt(iv16 + b":" + key32)
        )
        self._cseq += 1
        assert self._sock is not None
        self._sock.sendall(
            f"DESCRIBE {self._info.url} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            "Accept: application/sdp\r\n"
            f"Authorization: SEP DATA=\"{sep_data.decode()}\"\r\n"
            f"Key: {key_hdr.decode()}\r\n"
            f"Identification: {ident.decode()}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Upgrade: StreamSystem4.1\r\n\r\n".encode()
        )
        head, sdp = self._read_sdp()
        status = self._status_of(head)
        if status != 200:
            raise StreamError(f"Authenty DESCRIBE failed: HTTP {status}")
        return sdp

    def play(self) -> str:
        """DESCRIBE(authed) + SETUP + PLAY. Returns the RTSP session id."""
        self.describe_authed()
        self._cseq += 1
        head, _ = self._request(
            f"SETUP {self._info.url}/trackID=1 RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=0\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Upgrade: StreamSystem4.1\r\n\r\n"
        )
        m = re.search(r"Session: ([\w;]+)", head)
        self._session = m.group(1) if m else "0"
        self._cseq += 1
        self._request(
            f"PLAY {self._info.url} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            f"Session: {self._session}\r\n"
            "Range: npt=now-\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Upgrade: StreamSystem4.1\r\n\r\n"
        )
        return self._session or "0"

    def teardown(self) -> None:
        """Best-effort TEARDOWN (ignores errors)."""
        if self._sock is None or not self._session:
            return
        try:
            self._cseq += 1
            self._sock.sendall(
                f"TEARDOWN {self._info.url} RTSP/1.0\r\n"
                f"CSeq: {self._cseq}\r\n"
                f"Session: {self._session}\r\n"
                f"User-Agent: {_USER_AGENT}\r\n\r\n".encode()
            )
        except OSError:
            pass

    def close(self) -> None:
        """TEARDOWN + close socket."""
        if self._sock is not None:
            self.teardown()
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # -- media -----------------------------------------------------------

    def _next_interleaved(self) -> tuple[int, bytes]:
        """Read the next ``$<ch><len>…`` frame from the socket."""
        assert self._sock is not None
        while len(self._buf) < 4:
            chunk = self._sock.recv(_READ_CHUNK)
            if not chunk:
                raise StreamError("EOF in interleaved stream")
            self._buf += chunk
        if self._buf[0] != 0x24:
            # resync to first '$'
            idx = self._buf.find(b"$")
            if idx < 0:
                self._buf = b""
                return self._next_interleaved()
            self._buf = self._buf[idx:]
        ch = self._buf[1]
        ln = struct.unpack(">H", self._buf[2:4])[0]
        while len(self._buf) < 4 + ln:
            chunk = self._sock.recv(_READ_CHUNK)
            if not chunk:
                raise StreamError("EOF mid-packet")
            self._buf += chunk
        frame = self._buf[4 : 4 + ln]
        self._buf = self._buf[4 + ln :]
        return ch, frame

    @staticmethod
    def _rtp_payload(pkt: bytes) -> bytes | None:
        """Strip RTP header; None for non-video/short packets."""
        if len(pkt) < 12:
            return None
        if pkt[1] & 0x7F != 96:  # PT 96 = video
            return None
        hdr = 12 + (pkt[0] & 0x0F) * 4
        if pkt[0] & 0x10:  # extension header
            if len(pkt) < hdr + 4:
                return None
            hdr += 4 + struct.unpack(">H", pkt[hdr + 2 : hdr + 4])[0] * 4
        if hdr >= len(pkt):
            return None
        return pkt[hdr:]

    def h264_chunks(self, max_seconds: float | None = None) -> Iterator[bytes]:
        """Yield Annex-B NAL units as they arrive (blocking generator)."""
        deadline = time.monotonic() + max_seconds if max_seconds else None
        assert self._sock is not None
        while deadline is None or time.monotonic() < deadline:
            ch, pkt = self._next_interleaved()
            if ch != 0:
                continue
            payload = self._rtp_payload(pkt)
            if payload is None:
                continue
            yield from self._depak.feed(payload)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def capture_h264(info: StreamInfo, seconds: float = 3.0, timeout: float = 10.0) -> bytes:
    """Connect, play and collect ``seconds`` of Annex-B H.264, then stop."""
    out = bytearray()
    with AuthentyStreamClient(info, timeout=timeout) as cli:
        cli.play()
        deadline = time.monotonic() + seconds
        for nal in cli.h264_chunks():
            out += nal
            # keep reading a little past deadline to finish the current frame
            if time.monotonic() >= deadline and (nal[4] & 0x1F) in (1, 5):
                break
    return bytes(out)


def snapshot_jpeg(
    info: StreamInfo,
    seconds: float = 3.0,
    quality: int = 2,
    timeout: float = 10.0,
) -> bytes | None:
    """Grab a live JPEG frame: capture H.264 then decode one frame via ffmpeg.

    Returns None when ffmpeg is unavailable or no frame could be decoded.
    """
    h264 = capture_h264(info, seconds=seconds, timeout=timeout)
    if not h264:
        return None
    # trim to first SPS so ffmpeg starts on a clean GOP
    sps = h264.find(b"\x00\x00\x00\x01\x67")
    if sps > 0:
        h264 = h264[sps:]
    try:
        return _decode_first_jpeg(h264, quality, timeout)
    except (OSError, subprocess.SubprocessError):
        # ffmpeg missing or failed to spawn
        return None


def _decode_first_jpeg(h264: bytes, quality: int, timeout: float) -> bytes | None:
    """Decode the first frame of Annex-B H.264 into a JPEG via ffmpeg."""
    with tempfile.NamedTemporaryFile(suffix=".h264", delete=False) as tf:
        tf.write(h264)
        raw_path = tf.name
    jpg_path = raw_path + ".jpg"
    try:
        proc = subprocess.run(
            [
                "ffmpeg",
                "-v",
                "error",
                "-err_detect",
                "ignore_err",
                "-i",
                raw_path,
                "-frames:v",
                "1",
                "-q:v",
                str(quality),
                "-y",
                "-update",
                "1",
                jpg_path,
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode == 0 and os.path.exists(jpg_path):
            with open(jpg_path, "rb") as f:
                return f.read()
        return None
    finally:
        for path in (raw_path, jpg_path):
            try:
                os.remove(path)
            except OSError:
                pass
