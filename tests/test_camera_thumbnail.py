"""
Tests for camera thumbnail functionality — get_camera_elements parsing
and get_camera_thumbnail raw-HTTP fetch.

Note: get_camera_elements tests verify the mapping logic by injecting
pre-parsed data via a mocked _call() (same approach as test_discovery.py).
get_camera_thumbnail tests exercise the real method against a mocked
httpx transport.
"""

from unittest.mock import patch

import httpx
import pytest

from hikcentral_bumblebee import BumblebeeClient, HikCentralError
from tests.conftest import FakeResponse

# ---------------------------------------------------------------------------
# CameraElement-shaped response data (mirrors real responses:
# top level {"ErrorCode": "0", "Data": {"CameraElementList": {...}}})
# ---------------------------------------------------------------------------

FULL_ELEMENT_RESPONSE = {
    "ErrorCode": "0",
    "Data": {
        "CameraElementList": {
            "CameraElement": [
                {
                    "ID": "240",
                    "Name": "cam",
                    "Encoder": {
                        "Address": "192.0.2.40",
                        "UserName": "encuser",
                        "Password": "encpass",
                    },
                    "Camera": {
                        "RelatedChannelAddress": "192.0.2.41",
                        "RelatedChannelUserName": "chanuser",
                        "No": "1",
                    },
                    "ThumbnailInfo": {"Url": "Vsm://something"},
                }
            ]
        }
    },
}

ENCODER_ONLY_RESPONSE = {
    "ErrorCode": "0",
    "Data": {
        "CameraElementList": {
            "CameraElement": [
                {
                    "ID": "241",
                    "Name": "enc-only",
                    "Encoder": {
                        "Address": "192.0.2.40",
                        "UserName": "encuser",
                        "Password": "encpass",
                    },
                }
            ]
        }
    },
}

BARE_ELEMENT_RESPONSE = {
    "ErrorCode": "0",
    "Data": {"CameraElementList": {"CameraElement": [{"ID": "1", "Name": "x"}]}},
}

SINGLE_ELEMENT_UNWRAPPED_RESPONSE = {
    "ErrorCode": "0",
    "Data": {
        "CameraElementList": {
            # Server returns a single item as a dict, not wrapped in a list
            "CameraElement": {"ID": "1", "Name": "solo"}
        }
    },
}


class TestGetCameraElements:
    def test_full_element_camera_wins_over_encoder(self, mock_client):
        """Camera fields take precedence over Encoder fields."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: FULL_ELEMENT_RESPONSE

        cams = cli.get_camera_elements()
        assert len(cams) == 1
        cam = cams[0]
        assert cam.address == "192.0.2.41"
        assert cam.username == "chanuser"
        assert cam.password == "encpass"
        assert cam.thumbnail_url == "Vsm://something"

    def test_encoder_only_falls_back_to_encoder(self, mock_client):
        """Without a Camera block, Encoder address/username are used."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: ENCODER_ONLY_RESPONSE

        cams = cli.get_camera_elements()
        assert len(cams) == 1
        cam = cams[0]
        assert cam.address == "192.0.2.40"
        assert cam.username == "encuser"
        assert cam.thumbnail_url is None

    def test_bare_element_all_fields_none(self, mock_client):
        """An element without sub-blocks yields None for all optional fields."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: BARE_ELEMENT_RESPONSE

        cams = cli.get_camera_elements()
        assert len(cams) == 1
        cam = cams[0]
        assert cam.address is None
        assert cam.username is None
        assert cam.password is None
        assert cam.thumbnail_url is None

    def test_single_element_dict_unwrapped_to_list(self, mock_client):
        """A single CameraElement returned as a dict still yields a 1-element list."""
        cli, _ = mock_client
        cli._call = lambda path, logical="GET", body_obj=None: SINGLE_ELEMENT_UNWRAPPED_RESPONSE

        cams = cli.get_camera_elements()
        assert isinstance(cams, list)
        assert len(cams) == 1
        assert cams[0].id == "1"
        assert cams[0].name == "solo"


class TestGetCameraThumbnail:
    def test_success_returns_jpeg_bytes(self, mock_client):
        """200 + image content-type returns the raw JPEG bytes."""
        cli, mock_http = mock_client
        jpeg = b"\xff\xd8\xff\xe0JPEG"
        mock_http.get.return_value = FakeResponse(
            "", status_code=200, content=jpeg, headers={"Content-Type": "image/jpeg"}
        )

        result = cli.get_camera_thumbnail("240")

        assert result == jpeg
        assert mock_http.get.call_count == 1
        url = mock_http.get.call_args.args[0]
        assert "/ISAPI/Bumblebee/CameraElements/240/Thumbnail?SID=test-sid-abc" in url
        headers = mock_http.get.call_args.kwargs.get("headers", {})
        assert "AppendInfo" in headers

    def test_non_200_returns_none(self, mock_client):
        """Non-200 status (e.g. 403 forbidden) returns None."""
        cli, mock_http = mock_client
        mock_http.get.return_value = FakeResponse("", status_code=403)

        assert cli.get_camera_thumbnail("240") is None

    def test_non_image_content_type_returns_none(self, mock_client):
        """Offline cameras return XML with 200 — must be rejected."""
        cli, mock_http = mock_client
        mock_http.get.return_value = FakeResponse(
            "", status_code=200, content=b"<xml/>", headers={"Content-Type": "application/xml"}
        )

        assert cli.get_camera_thumbnail("240") is None

    def test_transport_error_returns_none(self, mock_client):
        """Network-level failures are swallowed and return None."""
        cli, mock_http = mock_client
        mock_http.get.side_effect = httpx.ConnectError("boom")

        assert cli.get_camera_thumbnail("240") is None

    def test_not_logged_in_raises(self):
        """get_camera_thumbnail before login() raises HikCentralError."""
        with patch("hikcentral_bumblebee.client.httpx.Client"):
            cli = BumblebeeClient("https://fake", "u", "p")
            with pytest.raises(HikCentralError):
                cli.get_camera_thumbnail("1")
