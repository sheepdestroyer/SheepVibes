import logging
import urllib.error
from unittest.mock import MagicMock
import pytest
import feedparser
from backend import feed_service

@pytest.fixture(autouse=True)
def _set_cache_redis_port(monkeypatch):
    """Ensure CACHE_REDIS_PORT is set for tests."""
    monkeypatch.setenv("CACHE_REDIS_PORT", "6380")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sheepvibes_test")

def test_fetch_feed_sends_conditional_headers(mocker):
    """Test that fetch_feed adds If-None-Match and If-Modified-Since headers."""
    mock_build_opener = mocker.patch("backend.feed_service.urllib.request.build_opener")
    mock_open = mock_build_opener.return_value.open
    mock_response = MagicMock()
    mock_response.read.return_value = b"<rss></rss>"
    mock_response.__enter__.return_value = mock_response
    mock_open.return_value = mock_response

    # Mock DNS with safe IP
    mocker.patch("backend.feed_service.socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 80))])

    url = "http://example.com/feed"
    etag = "test-etag"
    last_modified = "Sat, 29 Oct 2024 19:43:31 GMT"

    feed_service.fetch_feed(url, etag=etag, last_modified=last_modified)

    assert mock_open.called
    req = mock_open.call_args[0][0]
    # Use get_header for case-insensitive lookup
    assert req.get_header("If-none-match") == etag
    assert req.get_header("If-modified-since") == last_modified

def test_fetch_feed_handles_304(mocker):
    """Test that fetch_feed returns status=304 when server returns 304."""
    mock_build_opener = mocker.patch("backend.feed_service.urllib.request.build_opener")

    # Mock opener.open raising HTTPError 304
    mock_http_error = urllib.error.HTTPError(
        url="http://example.com/feed",
        code=304,
        msg="Not Modified",
        hdrs={},
        fp=None
    )
    mock_build_opener.return_value.open.side_effect = mock_http_error

    # Mock DNS with safe IP
    mocker.patch("backend.feed_service.socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 80))])

    result = feed_service.fetch_feed("http://example.com/feed", etag="old-etag")

    assert result is not None
    assert result.status == 304
    assert result.debug_message == "Not Modified"

def test_fetch_feed_captures_response_headers(mocker):
    """Test that fetch_feed captures ETag and Last-Modified from 200 OK response."""
    mock_build_opener = mocker.patch("backend.feed_service.urllib.request.build_opener")
    mock_response = MagicMock()
    mock_response.read.return_value = b"<rss></rss>"
    mock_response.getheader.side_effect = lambda k: {
        "ETag": "new-etag",
        "Last-Modified": "Sun, 30 Oct 2024 10:00:00 GMT",
        "Content-Length": "100"
    }.get(k)
    mock_response.__enter__.return_value = mock_response
    mock_build_opener.return_value.open.return_value = mock_response

    # Mock DNS with safe IP
    mocker.patch("backend.feed_service.socket.getaddrinfo", return_value=[(2, 1, 6, '', ('8.8.8.8', 80))])
    mocker.patch("backend.feed_service.feedparser.parse", return_value=feedparser.FeedParserDict(entries=[], bozo=0))

    result = feed_service.fetch_feed("http://example.com/feed")

    assert result.http_etag == "new-etag"
    assert result.http_last_modified == "Sun, 30 Oct 2024 10:00:00 GMT"
