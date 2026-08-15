"""
RED phase: tests for DoorAction — raw HTTP PUT without MT parameter.

CRITICAL: door_action() must use client.put() directly, NOT client.post(url?SID=...&MT=PUT).
With MT=PUT the server returns ErrorCode 6.
Body: <DoorElementOperation><Action>N</Action><Direction>0</Direction></DoorElementOperation>
"""

import pytest
from unittest.mock import patch


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


LOGIN_RESPONSE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<Login>"
    "<SID>sid</SID>"
    "<UserID>1</UserID>"
    "<EncryInfo>"
    "<Challenge>c</Challenge>"
    "<Iterations>100</Iterations>"
    "<EncryMode>1</EncryMode>"
    "</EncryInfo>"
    "</Login>"
    "</Data>"
    "</Response>"
)

DOOR_ACTION_OK = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<DoorElementOperation><ErrorCode>0</ErrorCode></DoorElementOperation>"
    "</Data>"
    "</Response>"
)

DOOR_ACTION_NOT_FOUND = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<DoorElementOperation><ErrorCode>975</ErrorCode></DoorElementOperation>"
    "</Data>"
    "</Response>"
)


class TestDoorAction:
    """door_action uses RAW HTTP PUT — no MT= parameter."""

    def _login_cli(self):
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)
            mock_client.put.return_value = FakeResponse(DOOR_ACTION_OK)
            cli = BumblebeeClient("https://fake", "u", "p")
            cli.login()
            return cli, mock_client

    def test_door_action_is_http_put_not_post(self):
        """door_action must call httpx.Client.put(), NOT post()."""
        cli, mock_client = self._login_cli()
        cli.door_action(door_id=123, action=1)

        assert mock_client.put.called, "door_action must use httpx.Client.put()"

    def test_door_action_url_contains_no_mt_param(self):
        """door_action PUT URL must NOT contain &MT= or ?MT=."""
        cli, mock_client = self._login_cli()
        cli.door_action(door_id=996, action=1)

        put_call = mock_client.put.call_args
        url = put_call.args[0] if put_call.args else put_call.kwargs.get("url", "")
        assert "MT=" not in url, f"PUT URL must not contain MT= parameter: {url}"
        assert "SID=" in url, f"PUT URL must contain SID=: {url}"
        assert "/DoorAction" in url, f"PUT URL must contain /DoorAction: {url}"

    def test_door_action_body_action_1_unlocks(self):
        """action=1 must produce <Action>1</Action> in XML body."""
        cli, mock_client = self._login_cli()
        cli.door_action(door_id=996, action=1)

        body = mock_client.put.call_args.kwargs.get("content", b"")
        body_str = body.decode() if isinstance(body, bytes) else body
        assert "<Action>1</Action>" in body_str
        assert "<Direction>0</Direction>" in body_str

    def test_door_action_body_action_2_locks(self):
        """action=2 must produce <Action>2</Action> in XML body."""
        cli, mock_client = self._login_cli()
        cli.door_action(door_id=996, action=2)

        body = mock_client.put.call_args.kwargs.get("content", b"")
        body_str = body.decode() if isinstance(body, bytes) else body
        assert "<Action>2</Action>" in body_str

    def test_door_action_includes_append_info_header(self):
        """door_action PUT must include AppendInfo header."""
        cli, mock_client = self._login_cli()
        cli.door_action(door_id=996, action=1)

        headers = mock_client.put.call_args.kwargs.get("headers", {})
        assert "AppendInfo" in headers
        assert len(headers["AppendInfo"]) > 0

    def test_door_action_returns_on_error_code_0(self):
        """door_action returns normally on ErrorCode 0."""
        cli, _ = self._login_cli()
        cli.door_action(door_id=996, action=1)  # must not raise

    def test_door_action_raises_on_error_code_975(self):
        """door_action raises HikCentralError on ErrorCode 975 (resource not found)."""
        from hikcentral_bumblebee import BumblebeeClient, HikCentralError

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)
            mock_client.put.return_value = FakeResponse(DOOR_ACTION_NOT_FOUND)
            cli = BumblebeeClient("https://fake", "u", "p")
            cli.login()
            with pytest.raises(HikCentralError) as exc_info:
                cli.door_action(door_id=999999, action=1)
            assert "975" in str(exc_info.value)
