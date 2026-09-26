"""
Unit tests for HTTP/2 feed downloading and fallback on HTTP 426 Upgrade Required.
"""

# pylint: disable=protected-access,unused-argument

import io
import urllib.error
from unittest.mock import MagicMock

import httpx
import pytest

from backend import feed_service
from backend.feed_service import MAX_FEED_RESPONSE_BYTES


def _create_mock_httpx_client():
    """Helper to create a MagicMock httpx.Client that supports context management."""
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    return client


def test_download_feed_content_primary_http2(mocker):
    """Test that _download_feed_content uses HTTP/2 as primary transport when safe_ip is available."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=b"<rss><channel><title>H2 Feed</title></channel></rss>",
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result == b"<rss><channel><title>H2 Feed</title></channel></rss>"
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_not_called()


def test_download_feed_content_fallback_to_urllib_on_transport_failure(mocker):
    """Test fallback to urllib opener when primary HTTP/2 download fails due to transport error."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"

    mock_response = MagicMock()
    mock_response.getheader.return_value = None
    mock_response.read.return_value = (
        b"<rss><channel><title>Urllib Feed</title></channel></rss>"
    )
    mock_response.__enter__.return_value = mock_response
    mock_opener.open.return_value = mock_response

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        side_effect=feed_service.HTTP2TransportError("Connection reset"),
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result == b"<rss><channel><title>Urllib Feed</title></channel></rss>"
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_definitive_rejection_no_urllib_fallback(mocker):
    """Test that definitive HTTP/2 rejection (None) aborts without falling back to urllib."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=None,
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result is None
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_not_called()


def test_download_feed_content_urllib_fallback_on_426(mocker):
    """Test that urllib fallback delegates to HTTP/2 if server returns HTTP 426 when HTTP/2 was not yet tried."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = None

    http_error_426 = urllib.error.HTTPError(
        url="https://example.com/feed",
        code=426,
        msg="Upgrade Required",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    mock_opener.open.side_effect = http_error_426

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=b"<rss><channel><title>H2 Feed</title></channel></rss>",
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result == b"<rss><channel><title>H2 Feed</title></channel></rss>"
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip=None,
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_urllib_426_retry_handles_transport_error(mocker):
    """Test that urllib 426 retry handles HTTP2TransportError gracefully and returns None."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = None

    http_error_426 = urllib.error.HTTPError(
        url="https://example.com/feed",
        code=426,
        msg="Upgrade Required",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    mock_opener.open.side_effect = http_error_426

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        side_effect=feed_service.HTTP2TransportError("Network error"),
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result is None
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip=None,
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_urllib_does_not_retry_http2_if_already_attempted(mocker):
    """Test that urllib 426 does not trigger HTTP/2 retry if HTTP/2 was already attempted."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"

    http_error_426 = urllib.error.HTTPError(
        url="https://example.com/feed",
        code=426,
        msg="Upgrade Required",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    mock_opener.open.side_effect = http_error_426

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        side_effect=feed_service.HTTP2TransportError("Connection failed"),
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result is None
    # HTTP/2 was only called once initially, not retried from urllib
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_non_426_http_error(mocker):
    """Test that urllib errors other than 426 return None without retrying HTTP/2."""
    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"

    http_error_500 = urllib.error.HTTPError(
        url="https://example.com/feed",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    mock_opener.open.side_effect = http_error_500

    mock_h2_download = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        side_effect=feed_service.HTTP2TransportError("Protocol error"),
    )

    result = feed_service._download_feed_content(
        mock_opener, "https://example.com/feed"
    )
    assert result is None
    mock_h2_download.assert_called_once_with(
        "https://example.com/feed",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_http2_success(mocker):
    """Test successful HTTP/2 download with IP pinning and SNI validation."""
    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.status_code = 200
    mock_response.http_version = "HTTP/2"
    mock_response.headers = {"content-length": "45"}
    mock_response.iter_bytes.return_value = [b"<rss>", b"<channel></channel></rss>"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_response

    captured_req = []

    def fake_build_request(method, url, headers=None):
        req = MagicMock()
        req.method = method
        req.url = url
        req.headers = headers or {}
        req.extensions = {}
        captured_req.append(req)
        return req

    mock_client.build_request.side_effect = fake_build_request
    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )

    assert result == b"<rss><channel></channel></rss>"
    assert len(captured_req) == 1
    req = captured_req[0]
    assert req.url == "https://93.184.216.34:443/feed"
    assert req.headers["Host"] == "example.com"
    assert req.extensions.get("sni_hostname") == "example.com"
    assert mock_response.close.called


def test_download_feed_content_http2_plain_http(mocker):
    """Test HTTP/2 fetch over plain HTTP (port 80, no SNI extension)."""
    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.iter_bytes.return_value = [b"<rss></rss>"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_response

    captured_req = []

    def fake_build_request(method, url, headers=None):
        req = MagicMock()
        req.extensions = {}
        captured_req.append(req)
        return req

    mock_client.build_request.side_effect = fake_build_request
    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "http://example.com/feed?q=1",
        safe_ip="93.184.216.34",
    )

    assert result == b"<rss></rss>"
    assert len(captured_req) == 1
    assert "sni_hostname" not in captured_req[0].extensions


def test_download_feed_content_http2_ipv6(mocker):
    """Test HTTP/2 fetch with IPv6 safe address formatting (bracketed)."""
    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.iter_bytes.return_value = [b"<rss></rss>"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_response

    captured_urls = []

    def fake_build_request(method, url, headers=None):
        captured_urls.append(url)
        req = MagicMock()
        req.extensions = {}
        return req

    mock_client.build_request.side_effect = fake_build_request
    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="2606:2800:220:1:248:1893:25c8:1946",
    )

    assert result == b"<rss></rss>"
    assert captured_urls[0] == "https://[2606:2800:220:1:248:1893:25c8:1946]:443/feed"


def test_download_feed_content_http2_resolves_ip_if_none(mocker):
    """Test that _download_feed_content_http2 resolves safe IP if not supplied."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("93.184.216.34", "example.com"),
    )

    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.iter_bytes.return_value = [b"<rss></rss>"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_response
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed", safe_ip=None
    )
    assert result == b"<rss></rss>"


def test_download_feed_content_http2_blocks_unsafe_ip(mocker):
    """Test that _download_feed_content_http2 aborts if URL resolves to unsafe IP."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url", return_value=(None, None)
    )
    result = feed_service._download_feed_content_http2(
        "https://private.lan/feed", safe_ip=None
    )
    assert result is None


def test_download_feed_content_http2_invalid_scheme():
    """Test that _download_feed_content_http2 rejects non-HTTP/HTTPS schemes."""
    result = feed_service._download_feed_content_http2(
        "ftp://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_redirect(mocker):
    """Test that _download_feed_content_http2 follows redirects with re-resolution and IP pinning."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("93.184.216.35", "redirected.example.com"),
    )

    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.headers = {"location": "https://redirected.example.com/rss.xml"}

    final_resp = MagicMock()
    final_resp.is_redirect = False
    final_resp.status_code = 200
    final_resp.headers = {}
    final_resp.iter_bytes.return_value = [
        b"<rss><channel><title>Final</title></channel></rss>"
    ]

    mock_client = _create_mock_httpx_client()
    mock_client.send.side_effect = [redirect_resp, final_resp]

    def fake_build_request(method, url, headers=None):
        req = MagicMock()
        req.extensions = {}
        return req

    mock_client.build_request.side_effect = fake_build_request
    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )

    assert result == b"<rss><channel><title>Final</title></channel></rss>"
    assert redirect_resp.close.called
    assert final_resp.close.called


def test_download_feed_content_http2_redirect_missing_location(mocker):
    """Test redirect with missing Location header fails gracefully."""
    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.headers = {}

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = redirect_resp
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_max_redirects_exceeded(mocker):
    """Test that exceeding max_redirects returns None."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("93.184.216.34", "example.com"),
    )

    def make_redirect_resp():
        resp = MagicMock()
        resp.is_redirect = True
        resp.headers = {"location": "https://example.com/feed"}
        return resp

    mock_client = _create_mock_httpx_client()
    mock_client.send.side_effect = [make_redirect_resp() for _ in range(10)]
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
        max_redirects=2,
    )
    assert result is None


def test_download_feed_content_http2_non_200_status(mocker):
    """Test that HTTP/2 fetch returning non-200 status code returns None."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 404

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_resp
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_content_length_exceeded(mocker):
    """Test that Content-Length header exceeding MAX_FEED_RESPONSE_BYTES is rejected."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.headers = {"content-length": str(MAX_FEED_RESPONSE_BYTES + 10)}

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_resp
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_stream_chunks_exceeded(mocker):
    """Test that downloaded stream exceeding MAX_FEED_RESPONSE_BYTES is rejected."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.iter_bytes.return_value = [b"A" * (MAX_FEED_RESPONSE_BYTES + 10)]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_resp
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_zip_bomb_protection(mocker):
    """Test that gzip-compressed content is rejected as zip bomb protection."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.iter_bytes.return_value = [b"\x1f\x8b\x08\x00some_gzipped_data"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_resp
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com/feed",
        safe_ip="93.184.216.34",
    )
    assert result is None


def test_download_feed_content_http2_network_exception(mocker):
    """Test that httpx network exceptions (Timeout, ConnectError) raise HTTP2TransportError."""
    mock_client = _create_mock_httpx_client()
    mock_client.send.side_effect = httpx.ConnectTimeout("Connection timed out")
    mock_req = MagicMock()
    mock_req.extensions = {}
    mock_client.build_request.return_value = mock_req

    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    with pytest.raises(feed_service.HTTP2TransportError, match="Connection timed out"):
        feed_service._download_feed_content_http2(
            "https://example.com/feed",
            safe_ip="93.184.216.34",
        )


def test_fetch_feed_end_to_end_primary_http2(mocker):
    """Test that fetch_feed uses HTTP/2 as primary transport without calling opener.open."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("107.167.83.50", "www.dumbingofage.com"),
    )

    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"
    mocker.patch("backend.feed_service._build_safe_opener", return_value=mock_opener)

    sample_feed_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
        <channel>
            <title>Dumbing of Age</title>
            <link>https://www.dumbingofage.com</link>
            <item>
                <title>Dozing</title>
                <link>https://www.dumbingofage.com/2026/comic/dozing/</link>
                <pubDate>Sat, 26 Sep 2026 04:01:00 +0000</pubDate>
            </item>
        </channel>
    </rss>"""

    mock_h2 = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=sample_feed_xml,
    )

    feed = feed_service.fetch_feed("https://www.dumbingofage.com/feed/")
    assert feed is not None
    assert feed.feed.title == "Dumbing of Age"
    assert len(feed.entries) == 1
    assert feed.entries[0].title == "Dozing"
    mock_h2.assert_called_once_with(
        "https://www.dumbingofage.com/feed/",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_not_called()


def test_fetch_feed_end_to_end_fallback_to_urllib_success(mocker):
    """Test that fetch_feed falls back to urllib when primary HTTP/2 download suffers transport error."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("107.167.83.50", "www.dumbingofage.com"),
    )

    sample_feed_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
        <channel>
            <title>Dumbing of Age</title>
            <link>https://www.dumbingofage.com</link>
            <item>
                <title>Dozing</title>
                <link>https://www.dumbingofage.com/2026/comic/dozing/</link>
                <pubDate>Sat, 26 Sep 2026 04:01:00 +0000</pubDate>
            </item>
        </channel>
    </rss>"""

    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"
    mock_response = MagicMock()
    mock_response.getheader.return_value = None
    mock_response.read.return_value = sample_feed_xml
    mock_response.__enter__.return_value = mock_response
    mock_opener.open.return_value = mock_response
    mocker.patch("backend.feed_service._build_safe_opener", return_value=mock_opener)

    mock_h2 = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        side_effect=feed_service.HTTP2TransportError("Connection reset"),
    )

    feed = feed_service.fetch_feed("https://www.dumbingofage.com/feed/")
    assert feed is not None
    assert feed.feed.title == "Dumbing of Age"
    assert len(feed.entries) == 1
    mock_h2.assert_called_once()
    mock_opener.open.assert_called_once()


def test_fetch_feed_end_to_end_definitive_rejection(mocker):
    """Test that fetch_feed cleanly aborts if primary HTTP/2 receives a definitive rejection (None)."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("107.167.83.50", "www.dumbingofage.com"),
    )

    mock_opener = MagicMock()
    mock_opener.safe_ip = "107.167.83.50"
    mocker.patch("backend.feed_service._build_safe_opener", return_value=mock_opener)

    mock_h2 = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=None,
    )

    feed = feed_service.fetch_feed("https://www.dumbingofage.com/feed/")
    assert feed is None
    mock_h2.assert_called_once_with(
        "https://www.dumbingofage.com/feed/",
        safe_ip="107.167.83.50",
    )
    mock_opener.open.assert_not_called()


def test_fetch_feed_end_to_end_with_426_fallback(mocker):
    """Test that fetch_feed falls back to urllib and handles 426 retry to HTTP/2 when opener has no safe_ip."""
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("107.167.83.50", "www.dumbingofage.com"),
    )

    mock_opener = MagicMock()
    mock_opener.safe_ip = None
    mocker.patch("backend.feed_service._build_safe_opener", return_value=mock_opener)

    http_error_426 = urllib.error.HTTPError(
        url="https://www.dumbingofage.com/feed/",
        code=426,
        msg="Upgrade Required",
        hdrs={},
        fp=io.BytesIO(b""),
    )
    mock_opener.open.side_effect = http_error_426

    sample_feed_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
        <channel>
            <title>Dumbing of Age</title>
            <link>https://www.dumbingofage.com</link>
            <item>
                <title>Dozing</title>
                <link>https://www.dumbingofage.com/2026/comic/dozing/</link>
                <pubDate>Sat, 26 Sep 2026 04:01:00 +0000</pubDate>
            </item>
        </channel>
    </rss>"""

    mock_h2 = mocker.patch(
        "backend.feed_service._download_feed_content_http2",
        return_value=sample_feed_xml,
    )

    feed = feed_service.fetch_feed("https://www.dumbingofage.com/feed/")
    assert feed is not None
    assert feed.feed.title == "Dumbing of Age"
    assert len(feed.entries) == 1
    assert feed.entries[0].title == "Dozing"
    mock_h2.assert_called_once_with(
        "https://www.dumbingofage.com/feed/",
        safe_ip=None,
    )
    mock_opener.open.assert_called_once()


def test_download_feed_content_http2_custom_port(mocker):
    """Test HTTP/2 fetch with non-standard port formats Host header with port."""
    mock_response = MagicMock()
    mock_response.is_redirect = False
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.iter_bytes.return_value = [b"<rss></rss>"]

    mock_client = _create_mock_httpx_client()
    mock_client.send.return_value = mock_response

    captured_req = []

    def fake_build_request(method, url, headers=None):
        req = MagicMock()
        req.extensions = {}
        req.url = url
        req.headers = headers or {}
        captured_req.append(req)
        return req

    mock_client.build_request.side_effect = fake_build_request
    mocker.patch("backend.feed_service.httpx.Client", return_value=mock_client)

    result = feed_service._download_feed_content_http2(
        "https://example.com:8443/feed",
        safe_ip="93.184.216.34",
    )

    assert result == b"<rss></rss>"
    assert len(captured_req) == 1
    assert captured_req[0].url == "https://93.184.216.34:8443/feed"
    assert captured_req[0].headers["Host"] == "example.com:8443"
    assert captured_req[0].extensions.get("sni_hostname") == "example.com"
