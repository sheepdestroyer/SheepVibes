import os
from unittest.mock import MagicMock

import pytest

from . import feed_service


@pytest.fixture(autouse=True)
def _set_cache_redis_port(monkeypatch):
    # Keep CI-configurable value; fall back to a non-default test port if unset.
    monkeypatch.setenv(
        "CACHE_REDIS_PORT",
        os.environ.get("CACHE_REDIS_PORT", "6380"),
    )


def test_fetch_feed_blocks_external_dtd(mock_network, caplog):
    """Test that external DTDs are blocked when forbid_external=True and logged safely."""
    mock_network.read.return_value = b'<!DOCTYPE foo SYSTEM "http://example.com/dtd">'

    # Include raw newlines and carriage returns in the URL to exercise log-injection hardening.
    url = "http://example.com/ext_dtd.xml\nwith\nnewline\rand\rcarriagereturn"

    import logging

    with caplog.at_level(logging.WARNING):
        result = feed_service.fetch_feed(url)

    # The unsafe XML should still be blocked.
    assert result is None

    # Ensure a warning was logged about blocking unsafe XML.
    warning_records = [
        record for record in caplog.records
        if record.levelno == logging.WARNING
    ]
    assert warning_records, "Expected a WARNING log entry when unsafe XML is blocked"

    messages = [record.getMessage() for record in warning_records]
    combined = " ".join(messages)

    # Raw newlines/carriage returns must not appear in the log message.
    assert "\n" not in combined
    assert "\r" not in combined

    # The sanitized URL (with escaped newlines/carriage returns) should be present.
    # Note: The _sanitize_url_for_log function replaces \n with \\n and \r with \\r.
    # In the log string, we expect to see literal backslashes.
    assert (
        "http://example.com/ext_dtd.xml\\nwith\\nnewline\\rand\\rcarriagereturn"
        in combined)


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


def create_feed_with_safe_dtd():
    return b"""<?xml version="1.0"?>
<!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN"
            "http://my.netscape.com/publish/formats/rss-0.91.dtd">
<rss version="0.91">
  <channel>
    <title>Safe DTD Feed</title>
  </channel>
</rss>"""


@pytest.fixture
def mock_network(mocker):
    """Mocks network calls and returns the urlopen mock's response object for configuration."""
    mocker.patch(
        "backend.feed_service.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")
    mock_build_opener = mocker.patch(
        "backend.feed_service.urllib.request.build_opener")

    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response

    # Support both direct urlopen (HTTP) and opener.open (HTTPS)
    mock_urlopen.return_value = mock_response
    mock_build_opener.return_value.open.return_value = mock_response

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


def test_fetch_feed_blocks_malformed_xml(mock_network, mocker):
    """Test that malformed XML (which triggers SAXParseException) is NOW BLOCKED (Fail Closed policy)."""
    mock_network.read.return_value = create_malformed_xml()

    # We mock feedparser just to ensure it's NOT called
    mock_feedparser = mocker.patch("backend.feed_service.feedparser.parse")

    url = "http://example.com/malformed.xml"
    result = feed_service.fetch_feed(url)

    # STRICT MODE: Must be blocked
    assert result is None
    # Check that feedparser was NEVER called
    mock_feedparser.assert_not_called()


def test_fetch_feed_blocks_dtd_with_external_reference(mock_network):
    """Test that feeds with 'safe' DTDs (e.g. RSS 0.91) are BLOCKED if they contain external references (SSRF protection)."""
    mock_network.read.return_value = create_feed_with_safe_dtd()

    url = "http://example.com/safe_dtd.xml"
    result = feed_service.fetch_feed(url)


def test_fetch_feed_blocks_gzip_content(mock_network):
    """Test that content starting with GZIP magic bytes is blocked (Zip Bomb protection)."""
    # GZIP magic bytes \x1f\x8b followed by garbage
    mock_network.read.return_value = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x00\x00"

    url = "http://example.com/bomb.gz"
    result = feed_service.fetch_feed(url)

    assert result is None
