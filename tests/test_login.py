"""
RED phase: tests for login flow — write before implementation.

These tests define the expected behaviour:
- login() sends plain-password XML to CT=0 endpoint
- parses SID and EncryInfo{Challenge, Iterations}
- raises on non-zero ErrorCode
"""

from unittest.mock import patch

import pytest


class FakeResponse:
    """Minimal httpx.Response replacement — no httpx dependency in tests."""

    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


LOGIN_RESPONSE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<Login>"
    "<SID>test-session-id-12345</SID>"
    "<UserID>999</UserID>"
    "<EncryInfo>"
    "<Challenge>deadbeefcafebabe</Challenge>"
    "<Iterations>100</Iterations>"
    "<EncryMode>1</EncryMode>"
    "</EncryInfo>"
    "</Login>"
    "</Data>"
    "</Response>"
)

LOGIN_ERROR_RESPONSE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<Login>"
    "<ErrorCode>216</ErrorCode>"
    "<ErrorMsg>session invalid</ErrorMsg>"
    "</Login>"
    "</Data>"
    "</Response>"
)


class TestLogin:
    def test_login_sends_ct0_plain_password_xml(self):
        """login() POSTs plain-password XML to /ISAPI/Bumblebee/Login?CT=0."""
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)

            cli = BumblebeeClient("https://fake.example.com", "user", "pass")
            cli.login()

            call_args = mock_client.post.call_args
            url = call_args.args[0] if call_args.args else call_args.kwargs.get("url", "")
            assert "?CT=0" in url
            assert "/ISAPI/Bumblebee/Login" in url
            body = call_args.kwargs.get("content", b"")
            assert b"<Password>pass</Password>" in body
            assert b"<UserName>user</UserName>" in body

    def test_login_parses_sid_and_encry_info(self):
        """login() extracts SID, Challenge, Iterations from response."""
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)

            cli = BumblebeeClient("https://fake.example.com", "user", "pass")
            cli.login()

            assert cli.sid == "test-session-id-12345"
            assert cli._challenge == "deadbeefcafebabe"
            assert cli._iterations == 100

    def test_login_raises_on_error_code(self):
        """login() raises HikCentralError when ErrorCode != 0."""
        from hikcentral_bumblebee import BumblebeeClient, HikCentralError

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_ERROR_RESPONSE_XML)

            cli = BumblebeeClient("https://fake.example.com", "user", "pass")
            with pytest.raises(HikCentralError) as exc_info:
                cli.login()
            assert "216" in str(exc_info.value)

    def test_login_stores_password_for_key_derivation(self):
        """login() stores the plain password for later AES key derivation."""
        from hikcentral_bumblebee import BumblebeeClient

        with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)

            cli = BumblebeeClient("https://fake.example.com", "myuser", "myplainpass")
            cli.login()

            assert cli._password == "myplainpass"
