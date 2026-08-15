"""
HikCentral Bumblebee client.

Implements:
- Login (CT=0 plain-password XML)
- AES key derivation: MD5^Iterations(password + challenge)
- AppendInfo header: AES-CBC("<n>:<ne(n)>", key, IV=0001..0f)
- _call() — POST with SID, MT, AppendInfo, XML body
- _raw_put() — raw HTTP PUT without MT for DoorAction
- Relogin on ErrorCode 216
"""

from __future__ import annotations

import base64
import hashlib
import math
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from .models import (
    AccessController,
    Area,
    CameraElement,
    DoorElement,
    VideoIntercom,
)


class HikCentralError(Exception):
    """Raised on non-zero ErrorCode from HikCentral API."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(f"ErrorCode {code}: {message}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def _ne(n: float) -> int:
    """ne(n) formula from HikCentral Bumblebee protocol.

    t = |n·sin n|
    m = |n·cos n|
    if t < m: swap(t, m)
    if m == 0: m = t
    return int(6.28·m + 4·(t - m))
    """
    t = abs(n * math.sin(n))
    m = abs(n * math.cos(n))
    if t < m:
        t, m = m, t
    if m == 0:
        m = t
    return int(6.28 * m + 4 * (t - m))


def _derive_aes_key(password: str, challenge: str, iterations: int) -> str:
    """MD5^Iterations(password + challenge) — hex chain, 32 hex chars."""
    result = hashlib.md5((password + challenge).encode()).hexdigest()
    for _ in range(1, iterations):
        result = hashlib.md5(result.encode()).hexdigest()
    return result


def _xml_to_dict(element: ET.Element) -> Any:
    """Convert XML element to a dict, merging repeated child tags into lists."""
    # Only recurse if there are actual child elements (ignore whitespace text nodes)
    child_elements = [c for c in element if isinstance(c.tag, str)]
    if not child_elements:
        return element.text or ""

    d: dict[str, Any] = {}
    for child in child_elements:
        v = _xml_to_dict(child)
        if child.tag in d:
            existing = d[child.tag]
            if isinstance(existing, list):
                existing.append(v)
            else:
                d[child.tag] = [existing, v]
        else:
            d[child.tag] = v
    return d


def _parse_xml_response(xml_text: str) -> dict[str, Any]:
    """Parse HikCentral XML response into a dict."""
    try:
        root = ET.fromstring(xml_text)
        return _xml_to_dict(root)
    except ET.ParseError:
        return {"_raw": xml_text[:1000]}


def _check_error(data: dict[str, Any]) -> None:
    """Check response data for ErrorCode (any depth); raise HikCentralError if non-zero."""
    code = _find_error_code(data)
    if code is not None and code != 0:
        raise HikCentralError(code)


def _get_data(data: dict[str, Any]) -> dict[str, Any]:
    """Extract Data dict from response.

    Real server returns:  {ErrorModule, ErrorCode, Data}
    Test fixtures wrap in: {Response: {Data}}
    This helper handles both.
    """
    if "Response" in data:
        return data["Response"].get("Data", {})
    return data.get("Data", {})


def _obj_to_xml(obj: Any) -> str:
    """Serialize a Python object to XML string (simple cases)."""
    if isinstance(obj, dict):
        parts = [f"<{k}>{_obj_to_xml(v)}</{k}>" for k, v in obj.items()]
        return "".join(parts)
    elif isinstance(obj, list):
        return "".join(_obj_to_xml(item) for item in obj)
    else:
        return str(obj) if obj is not None else ""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class BumblebeeClient:
    """Client for HikCentral Bumblebee API (HikCentral Pro v2.x OverSea_Pro)."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self._password = password
        self._verify = verify

        self.sid: str | None = None
        self._aes_key: str | None = None
        self._challenge: str | None = None
        self._iterations: int | None = None
        self._token_key_num: int = 11

        self._client = httpx.Client(
            base_url=self.base_url,
            verify=self._verify,
            timeout=30.0,
            headers={
                "Accept": "application/xml, text/xml, */*;",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": "Mozilla/5.0",
            },
        )

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    def login(self) -> None:
        """Login to HikCentral — CT=0 plain-password XML.

        Stores SID, derives AES key from password+challenge.
        Raises HikCentralError on non-zero ErrorCode.
        """
        url = f"{self.base_url}/ISAPI/Bumblebee/Login?CT=0"
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f"<LoginRequest>"
            f"<UserName>{self.username}</UserName>"
            f"<Password>{self._password}</Password>"
            f"<LoginAddress>{self.base_url.split('://')[1].split(':')[0]}</LoginAddress>"
            f"<LoginModel>1</LoginModel>"
            f"<IsRSMWebLogin>0</IsRSMWebLogin>"
            f"</LoginRequest>"
        )

        resp = self._client.post(url, content=body.encode())
        data = _parse_xml_response(resp.text)

        try:
            login_data = data["Response"]["Data"]["Login"]
        except KeyError:
            # Fallback: some server variants omit the Response wrapper
            try:
                login_data = data["Data"]["Login"]
            except KeyError as exc:
                raise HikCentralError(-1, f"Unexpected login response structure: {data}") from exc

        _check_error(data)

        self.sid = login_data["SID"]
        encry_info = login_data["EncryInfo"]
        self._challenge = encry_info["Challenge"]
        self._iterations = int(encry_info["Iterations"])
        self._aes_key = _derive_aes_key(self._password, self._challenge, self._iterations)

    # -------------------------------------------------------------------------
    # AppendInfo
    # -------------------------------------------------------------------------

    def _build_append_info(self) -> str:
        """Build AppendInfo header value: AES-CBC("<n>:<ne(n)>", key, IV)."""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        if self._aes_key is None:
            raise HikCentralError(-1, "Not logged in — call login() first")

        n = self._token_key_num
        self._token_key_num += 1

        plaintext = f"{n}:{_ne(n)}".encode()
        encrypted = AES.new(
            bytes.fromhex(self._aes_key),
            AES.MODE_CBC,
            iv=IV,
        ).encrypt(pad(plaintext, 16))

        return base64.b64encode(encrypted).decode()

    # -------------------------------------------------------------------------
    # Core request helpers
    # -------------------------------------------------------------------------

    def _call(
        self,
        path: str,
        logical: str = "GET",
        body_obj: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated API call.

        POST to <path>?SID=<sid>&MT=<logical>
        body_obj is serialized to XML if provided.
        Parses XML response, checks ErrorCode.
        Re-logins on session expiry (ErrorCode 216).
        """
        if self.sid is None:
            raise HikCentralError(-1, "Not logged in — call login() first")

        url = f"{path}?SID={self.sid}&MT={logical}"
        headers = {"AppendInfo": self._build_append_info()}

        body_bytes = b""
        if body_obj is not None:
            body_xml = '<?xml version="1.0" encoding="UTF-8"?>' + _obj_to_xml(body_obj)
            body_bytes = body_xml.encode()

        resp = self._client.post(url, content=body_bytes, headers=headers)
        data = _parse_xml_response(resp.text)

        # Check for session expiry — re-login once
        if _find_error_code(data) == 216:
            self.login()
            return self._call(path, logical, body_obj)

        _check_error(data)
        return data

    def _raw_put(self, path: str, xml_body: str) -> dict[str, Any]:
        """Raw HTTP PUT without MT parameter (for DoorAction).

        AppendInfo header is required.
        """
        if self.sid is None:
            raise HikCentralError(-1, "Not logged in — call login() first")

        url = f"{path}?SID={self.sid}"
        headers = {"AppendInfo": self._build_append_info()}

        resp = self._client.put(url, content=xml_body.encode(), headers=headers)
        data = _parse_xml_response(resp.text)

        if _find_error_code(data) == 216:
            self.login()
            resp = self._client.put(url, content=xml_body.encode(), headers=headers)
            data = _parse_xml_response(resp.text)

        _check_error(data)
        return data

    # -------------------------------------------------------------------------
    # Door actions
    # -------------------------------------------------------------------------

    def door_action(self, door_id: str | int, action: int) -> None:
        """Send a door action.

        action: 1=open/unlock, 2=lock, 3=remain_unlocked, 4=remain_locked

        Uses RAW HTTP PUT without MT parameter.
        """
        door_id_str = str(door_id)
        xml_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<DoorElementOperation>"
            f"<Action>{action}</Action>"
            "<Direction>0</Direction>"
            "</DoorElementOperation>"
        )
        self._raw_put(
            f"/ISAPI/Bumblebee/ACS/DoorElements/{door_id_str}/DoorAction",
            xml_body,
        )

    # -------------------------------------------------------------------------
    # Discovery
    # -------------------------------------------------------------------------

    def get_areas(self) -> list[Area]:
        """List all areas."""
        data = self._call(
            "/ISAPI/Bumblebee/Areas",
            body_obj={"AreasRequest": {"AreaID": -1, "DepthTraversal": 0}},
        )
        area_data = _get_data(data)
        items = area_data.get("AreaList", {}).get("Area", [])
        if isinstance(items, dict):
            items = [items]
        return [
            Area(
                id=str(a["ID"]),
                name=a.get("Name", ""),
                parent_id=str(a["ParentAreaID"])
                if a.get("ParentAreaID") not in ("-1", None)
                else None,
            )
            for a in items
        ]

    def get_door_elements(self, area_id: int = -1) -> list[DoorElement]:
        """List door elements, optionally filtered by area."""
        data = self._call(
            "/ISAPI/Bumblebee/ACS/DoorElements",
            body_obj={"DoorElementsRequest": {"AreaID": area_id, "DepthTraversal": 0}},
        )
        elem_data = _get_data(data)
        items = elem_data.get("DoorElementList", {}).get("DoorElement", [])
        if isinstance(items, dict):
            items = [items]
        return [
            DoorElement(
                id=str(d["ID"]),
                name=d.get("BaseInfo", {}).get("Name", ""),
                online=_bool(d.get("BaseInfo", {}).get("Online", "0")),
            )
            for d in items
        ]

    def get_door(self, door_id: str | int) -> DoorElement:
        """Get detailed door info including DoorStatus."""
        data = self._call(f"/ISAPI/Bumblebee/ACS/DoorElements/{door_id}")
        elem_data = _get_data(data)
        elem = elem_data.get("DoorElement", {})

        base_info = elem.get("BaseInfo", {})
        door_status = elem.get("DoorStatus", {})
        access_ctrl = elem.get("AccessController", {})
        access_ctrl_base = access_ctrl.get("BaseInfo", {})
        door_no_info = elem.get("Door", {})
        cameras_raw = elem.get("AssociatedCameras", {})
        camera_list = cameras_raw.get("Camera", []) if cameras_raw else []
        if isinstance(camera_list, dict):
            camera_list = [camera_list]

        return DoorElement(
            id=str(elem.get("ID", "")),
            name=base_info.get("Name", ""),
            online=_bool(base_info.get("Online", "0")),
            magnet_state=_int(door_status.get("MagnetState")),
            lock_state=_int(door_status.get("LockState")),
            policy_state=_int(door_status.get("PolicyState")),
            overall_status=_int(door_status.get("OverallStatus")),
            controller_id=str(access_ctrl.get("ID", "")) or None,
            controller_address=access_ctrl_base.get("Address") or None,
            door_no=_int(door_no_info.get("No")),
            associated_cameras=[str(c.get("CameraID", "")) for c in camera_list],
        )

    def get_camera_elements(self) -> list[CameraElement]:
        """List camera elements.

        Parses the Encoder/Camera sub-blocks so each CameraElement carries
        the RTSP source (address, credentials) and the HikCentral thumbnail
        URL when the server provides one.
        """
        data = self._call(
            "/ISAPI/Bumblebee/CameraElements",
            body_obj={"CameraElementsRequest": {"AreaID": -1, "DepthTraversal": 0}},
        )
        cam_data = _get_data(data)
        items = cam_data.get("CameraElementList", {}).get("CameraElement", [])
        if isinstance(items, dict):
            items = [items]
        result: list[CameraElement] = []
        for c in items:
            enc = c.get("Encoder", {}) or {}
            cam = c.get("Camera", {}) or {}
            thumb = c.get("ThumbnailInfo", {}) or {}
            result.append(
                CameraElement(
                    id=str(c.get("ID", "")),
                    name=c.get("Name", ""),
                    address=(
                        cam.get("RelatedChannelAddress")
                        or enc.get("Address")
                        or None
                    ),
                    username=(
                        cam.get("RelatedChannelUserName")
                        or enc.get("UserName")
                        or None
                    ),
                    password=enc.get("Password") or None,
                    thumbnail_url=thumb.get("Url") or None,
                )
            )
        return result

    def get_camera_thumbnail(self, camera_id: str | int) -> bytes | None:
        """Fetch a single JPEG thumbnail for a camera element.

        HikCentral serves camera thumbnails as raw JPEG from
        ``/ISAPI/Bumblebee/CameraElements/{id}/Thumbnail``. This is a raw
        HTTP GET (no MT logical, no XML body); the response body IS the JPEG.
        Returns None on any failure (camera offline, session issue, etc.).
        """
        if self.sid is None:
            raise HikCentralError(-1, "Not logged in — call login() first")
        url = f"/ISAPI/Bumblebee/CameraElements/{camera_id}/Thumbnail?SID={self.sid}"
        try:
            resp = self._client.get(url, headers={"AppendInfo": self._build_append_info()})
            if resp.status_code != 200:
                return None
            ctype = resp.headers.get("Content-Type", "")
            if "image" not in ctype:
                return None
            return resp.content
        except httpx.HTTPError:
            return None

    def get_access_controllers(self) -> list[AccessController]:
        """List access controllers."""
        data = self._call(
            "/ISAPI/Bumblebee/ACS/Device/AccessControllers",
            body_obj={"AccessControllersRequest": {"AreaID": -1, "DepthTraversal": 0}},
        )
        ctrl_data = _get_data(data)
        items = ctrl_data.get("AccessControllerList", {}).get("AccessController", [])
        if isinstance(items, dict):
            items = [items]
        return [
            AccessController(
                id=str(a.get("ID", "")),
                name=a.get("BaseInfo", {}).get("Alias", ""),
                address=a.get("BaseInfo", {}).get("Address"),
            )
            for a in items
        ]

    def get_video_intercoms(self) -> list[VideoIntercom]:
        """List video intercoms."""
        data = self._call(
            "/ISAPI/Bumblebee/ACS/Device/VideoIntercoms",
            body_obj={"VideoIntercomsRequest": {"AreaID": -1, "DepthTraversal": 0}},
        )
        int_data = _get_data(data)
        items = int_data.get("VideoIntercomList", {}).get("VideoIntercom", [])
        if isinstance(items, dict):
            items = [items]
        return [
            VideoIntercom(
                id=str(v.get("ID", "")),
                name=v.get("BaseInfo", {}).get("Alias", ""),
            )
            for v in items
        ]

    def keepalive(self) -> None:
        """Send keepalive to maintain session."""
        self._call(
            "/ISAPI/Bumblebee/KeepLive",
            logical="POST",
            body_obj={"KeepLive": {"ClientAddress": ""}},
        )


def _bool(val: Any) -> bool:
    """Convert value to bool, handling XML 'true'/'false' strings."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def _int(val: Any) -> int | None:
    """Convert value to int or return None."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _find_error_code(data: dict[str, Any]) -> int | None:
    """Walk dict to find ErrorCode value."""

    def find(d: Any) -> int | None:
        if isinstance(d, dict):
            if "ErrorCode" in d:
                try:
                    return int(d["ErrorCode"])
                except (ValueError, TypeError):
                    return None
            for v in d.values():
                r = find(v)
                if r is not None:
                    return r
        elif isinstance(d, list):
            for item in d:
                r = find(item)
                if r is not None:
                    return r
        return None

    return find(data)
