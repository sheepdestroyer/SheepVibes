from unittest.mock import MagicMock
import os

import pytest

from . import feed_service


@pytest.fixture(autouse=True)
def _set_cache_redis_port(monkeypatch):
    # Keep CI-configurable value; fall back to a non-default test port if unset.
    monkeypatch.setenv(
        "CACHE_REDIS_PORT",
        os.environ.get("CACHE_REDIS_PORT", "6380"),
    )


# Helper to create a malicious XML string
def create_xxe_payload():
    return b"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><rss version="2.0"><channel><title>&xxe;</title></channel></rss>"""


def create_valid_feed():
    return b"""<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Valid Feed</title>
  </channel>
</rss>"""


def create_malformed_xml():
    return b"""<rss><channel><title>Unclosed Tag</title>"""


@pytest.fixture
def mock_network(mocker):
    """Mocks network calls and returns the urlopen mock's response object for configuration."""
    mocker.patch(
        "backend.feed_service.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")

    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    return mock_response


def test_fetch_feed_blocks_xxe(mock_network):
    """Test that fetch_feed detects and blocks XXE payloads."""
    mock_network.read.return_value = create_xxe_payload()

    url = "http://example.com/feed.xml"
    result = feed_service.fetch_feed(url)

    # Should be None because it was rejected
    assert result is None


def test_fetch_feed_allows_valid_xml(mock_network):
    """Test that fetch_feed allows valid XML."""
    mock_network.read.return_value = create_valid_feed()

    url = "http://example.com/valid.xml"
    result = feed_service.fetch_feed(url)

    assert result is not None
    assert result.feed.title == "Valid Feed"


def test_fetch_feed_allows_malformed_xml_passed_to_feedparser(
        mocker, mock_network):
    """Test that malformed XML (which triggers SAXParseException) is NOT blocked and passed to feedparser."""
    mock_network.read.return_value = create_malformed_xml()

    # Mock feedparser to verify we pass the content through
    mock_feedparser = mocker.patch("backend.feed_service.feedparser.parse")
    mock_feedparser.return_value = MagicMock(bozo=False)

    url = "http://example.com/malformed.xml"
    feed_service.fetch_feed(url)

    # Verify feedparser was called with the content
    mock_feedparser.assert_called_once_with(create_malformed_xml())
