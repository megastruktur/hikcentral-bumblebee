"""Tests for the streaming module: StreamInfo parsing + H264 depacketizer."""

import struct

import pytest

from hikcentral_bumblebee.streaming import (
    AuthentyStreamClient,
    H264RtpDepacketizer,
    StreamError,
    StreamInfo,
    parse_common_url,
)

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus><ErrorModule>0</ErrorModule><ErrorCode>0</ErrorCode>
<Data><CommonUrlList><totalNum>1</totalNum><commonUrl>
<elementID>64</elementID>
<url>[sms:preview]rtsp://hikcentral.example.com:554/hikvision://192.0.2.22:8000:32:0</url>
<transmode>0</transmode><SMSWebSocketPort>559</SMSWebSocketPort>
<SMSToken><Enable>1</Enable><Token>SElLSU5WQUxJREdFTkVSQVRFRFRPS0VOSlVaR0pGUVU9=</Token></SMSToken>
<UserName>streamuser</UserName><PassWord>streampass</PassWord><StreamSecretKey/>
</commonUrl></CommonUrlList></Data></ResponseStatus>
"""


class TestStreamInfo:
    def test_parse_full_xml(self):
        info = parse_common_url(SAMPLE_XML)
        assert info.url == "rtsp://hikcentral.example.com:554/hikvision://192.0.2.22:8000:32:0"
        assert info.username == "streamuser"
        assert info.password == "streampass"
        assert info.token_b64.startswith("SElL")

    def test_host(self):
        info = parse_common_url(SAMPLE_XML)
        assert info.host == "hikcentral.example.com"

    def test_from_common_url_dict(self):
        info = StreamInfo.from_common_url(
            {
                "url": "[sms:preview]rtsp://1.2.3.4:554/hikvision://203.0.113.1:8000:1:0",
                "UserName": "u",
                "PassWord": "p",
                "SMSToken": {"Token": "T0s="},
            }
        )
        assert info.url == "rtsp://1.2.3.4:554/hikvision://203.0.113.1:8000:1:0"
        assert info.token_b64 == "T0s="

    def test_from_common_url_missing_token(self):
        with pytest.raises(StreamError):
            StreamInfo.from_common_url({"url": "rtsp://x/y", "SMSToken": {}})

    def test_missing_common_url_element(self):
        with pytest.raises(StreamError):
            parse_common_url("<ResponseStatus><ErrorCode>0</ErrorCode></ResponseStatus>")


class TestDepacketizer:
    def _nal(self, t: int) -> bytes:
        return bytes([(0x60 | t)]) + bytes([0xAB] * 4)

    def test_single_nal(self):
        d = H264RtpDepacketizer()
        nal = self._nal(7)
        out = d.feed(nal)
        assert out == [b"\x00\x00\x00\x01" + nal]

    def test_sps_pps_idr_sequence(self):
        d = H264RtpDepacketizer()
        sps, pps, idr = self._nal(7), self._nal(8), self._nal(5)
        out = d.feed(sps) + d.feed(pps) + d.feed(idr)
        assert [o[4] & 0x1F for o in out] == [7, 8, 5]

    def test_fu_a_reassembly(self):
        d = H264RtpDepacketizer()
        # FU-A of NAL type 5 in 3 fragments
        fu_ind = bytes([0xE0 | 28])
        start = fu_ind + bytes([0x80 | 5]) + b"\xaa\xbb"
        cont = fu_ind + bytes([0x00 | 5]) + b"\xcc"
        end = fu_ind + bytes([0x40 | 5]) + b"\xdd"
        assert d.feed(start) == []
        assert d.feed(cont) == []
        out = d.feed(end)
        assert out == [b"\x00\x00\x00\x01" + bytes([0xE0 | 5]) + b"\xaa\xbb\xcc\xdd"]

    def test_fu_a_missing_start_ignored(self):
        d = H264RtpDepacketizer()
        cont = bytes([0xE0 | 28, 0x05, 0x11])
        assert d.feed(cont) == []

    def test_stap_a(self):
        d = H264RtpDepacketizer()
        n1, n2 = self._nal(7), self._nal(8)
        payload = (
            bytes([0x60 | 24]) + struct.pack(">H", len(n1)) + n1 + struct.pack(">H", len(n2)) + n2
        )
        out = d.feed(payload)
        assert out == [b"\x00\x00\x00\x01" + n1, b"\x00\x00\x00\x01" + n2]

    def test_skips_zero_len_payload(self):
        d = H264RtpDepacketizer()
        assert d.feed(b"") == []

    def test_flush_drops_partial(self):
        d = H264RtpDepacketizer()
        start = bytes([0xE0 | 28, 0x80 | 1, 0x01])
        d.feed(start)
        d.flush()
        end = bytes([0xE0 | 28, 0x40 | 1, 0x02])
        assert d.feed(end) == []  # continuation without start after flush


class TestRtpPayloadStrip:
    def _pkt(self, pt=96, csrc=0, payload=b"\x67\x4d\x00\x01"):
        b0 = 0x80 | csrc
        return (
            bytes([b0, 0x80 | pt])  # V/P/X/CC + M/PT
            + b"\x00\x01"  # seq
            + b"\x00\x00\x00\x10"  # timestamp
            + b"\xde\xad\xbe\xef"  # SSRC
            + payload
        )

    def test_basic_strip(self):
        assert AuthentyStreamClient._rtp_payload(self._pkt()) == b"\x67\x4d\x00\x01"

    def test_pt_112_skipped(self):
        assert AuthentyStreamClient._rtp_payload(self._pkt(pt=112)) is None

    def test_short_packet_skipped(self):
        assert AuthentyStreamClient._rtp_payload(b"\x80\x60\x00") is None

    def test_crc_count(self):
        pkt = self._pkt(csrc=1, payload=b"\x67")
        pkt = pkt[:12] + b"\xff\xff\xff\xff" + pkt[12:]  # insert 1 CSRC word (4 bytes)
        assert AuthentyStreamClient._rtp_payload(pkt) == b"\x67"


# ---------------------------------------------------------------------------
# H265RtpDepacketizer (RFC 7798)
# ---------------------------------------------------------------------------


class TestH265Depacketizer:
    def test_single_nal(self):
        from hikcentral_bumblebee.streaming import H265RtpDepacketizer

        d = H265RtpDepacketizer()
        # NAL type 33 (SPS) in the 2-byte header: type<<1
        payload = bytes([(33 << 1), 0x01]) + b"\x12\x34"
        assert d.feed(payload) == [b"\x00\x00\x00\x01" + payload]

    def test_ap_two_nals(self):
        from hikcentral_bumblebee.streaming import H265RtpDepacketizer

        d = H265RtpDepacketizer()
        n1, n2 = b"\x42\x01\xaa", b"\x44\x01\xbb\xcc"
        ap = (
            bytes([(48 << 1), 0x00])
            + len(n1).to_bytes(2, "big")
            + n1
            + len(n2).to_bytes(2, "big")
            + n2
        )
        out = d.feed(ap)
        assert out == [b"\x00\x00\x00\x01" + n1, b"\x00\x00\x00\x01" + n2]

    def test_fu_reassembly(self):
        from hikcentral_bumblebee.streaming import H265RtpDepacketizer

        d = H265RtpDepacketizer()
        fu_type = 19  # IDR_W_RADL
        # payload header carries Type=49; FU header carries S|E|real type
        start = bytes([(49 << 1), 0x01]) + bytes([0x80 | fu_type]) + b"\x11\x22"
        cont = bytes([(49 << 1), 0x01]) + bytes([fu_type]) + b"\x33"
        end = bytes([(49 << 1), 0x01]) + bytes([0x40 | fu_type]) + b"\x44"
        assert d.feed(start) == []
        assert d.feed(cont) == []
        out = d.feed(end)
        assert len(out) == 1
        nal = out[0]
        assert nal[:4] == b"\x00\x00\x00\x01"
        # rebuilt 2-byte NAL header: F/LayerId/TID preserved, type = 19
        assert (nal[4] >> 1) & 0x3F == fu_type
        assert nal[5] == 0x01
        assert nal[6:] == b"\x11\x22\x33\x44"

    def test_short_payload_skipped(self):
        from hikcentral_bumblebee.streaming import H265RtpDepacketizer

        d = H265RtpDepacketizer()
        assert d.feed(b"\x50") == []
