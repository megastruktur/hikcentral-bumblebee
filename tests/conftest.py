"""
Pytest configuration and shared fixtures for hikcentral_bumblebee tests.
"""

import pytest
from unittest.mock import patch


class FakeResponse:
    """Minimal httpx.Response substitute — no httpx import needed in tests."""

    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Mock client factory
# ---------------------------------------------------------------------------

LOGIN_RESPONSE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Response>"
    "<Data>"
    "<Login>"
    "<SID>test-sid-abc</SID>"
    "<UserID>1</UserID>"
    "<EncryInfo>"
    "<Challenge>deadbeef</Challenge>"
    "<Iterations>100</Iterations>"
    "<EncryMode>1</EncryMode>"
    "</EncryInfo>"
    "</Login>"
    "</Data>"
    "</Response>"
)


@pytest.fixture
def mock_client():
    """Return a BumblebeeClient with a fully mocked httpx transport.

    The httpx.Client is mocked so all HTTP goes nowhere.
    Login is pre-seeded with LOGIN_RESPONSE_XML.
    """
    with patch("hikcentral_bumblebee.client.httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = FakeResponse(LOGIN_RESPONSE_XML)
        from hikcentral_bumblebee import BumblebeeClient

        cli = BumblebeeClient("https://fake", "u", "p")
        cli.login()
        yield cli, mock_client
