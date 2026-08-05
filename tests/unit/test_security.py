"""Unit tests for backend security fixes: feed URL scheme validation, SSL SNI port handling, and OPML export sanitization."""

import socket
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from backend.feed_service import SafeHTTPSConnection
from backend.models import Feed, Tab, db


def test_add_feed_rejects_invalid_schemes(client):
    """Test that add_feed rejects non-HTTP/HTTPS schemes (e.g. javascript:, file:, gopher:)."""
    invalid_urls = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/1",
        "ftp://example.com/rss.xml",
        "data:text/html,test",
    ]

    for url in invalid_urls:
        response = client.post(
            "/api/feeds",
            json={"url": url},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "Invalid feed URL scheme" in data["error"]


def test_update_feed_url_rejects_invalid_schemes(client):
    """Test that update_feed_url rejects non-HTTP/HTTPS schemes."""
    # First create a valid tab and feed
    tab = Tab(name="Security Tab", order=0)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(tab_id=tab.id, name="Valid Feed", url="http://example.com/rss.xml")
    db.session.add(feed)
    db.session.commit()

    invalid_urls = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/1",
    ]

    for url in invalid_urls:
        response = client.put(
            f"/api/feeds/{feed.id}",
            json={"url": url},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "Invalid feed URL scheme" in data["error"]


def test_safe_https_connection_sni_hostname_without_port(mocker):
    """Test that SafeHTTPSConnection extracts hostname without port for SSL SNI."""
    mock_sock = MagicMock()
    mock_create_conn = mocker.patch("socket.create_connection", return_value=mock_sock)

    mock_ssl_context = MagicMock()
    mock_wrapped_socket = MagicMock()
    mock_ssl_context.wrap_socket.return_value = mock_wrapped_socket

    # Test host with port
    conn_with_port = SafeHTTPSConnection("example.com:8443", safe_ip="192.0.2.1", port=8443)
    conn_with_port._context = mock_ssl_context
    conn_with_port.connect()

    assert mock_create_conn.call_args[0][0] == ("192.0.2.1", 8443)
    mock_ssl_context.wrap_socket.assert_called_with(
        mock_sock,
        server_hostname="example.com",
    )

    # Test host without port
    mock_ssl_context.wrap_socket.reset_mock()
    conn_no_port = SafeHTTPSConnection("example.com", safe_ip="192.0.2.1", port=443)
    conn_no_port._context = mock_ssl_context
    conn_no_port.connect()

    assert mock_create_conn.call_args[0][0] == ("192.0.2.1", 443)
    mock_ssl_context.wrap_socket.assert_called_with(
        mock_sock,
        server_hostname="example.com",
    )


def test_opml_export_sanitizes_xml_control_characters(client):
    """Test that OPML export sanitizes XML control characters from tab and feed metadata."""
    tab = Tab(name="Tab\x00Name\x07With\x0bControl", order=0)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(
        tab_id=tab.id,
        name="Feed\x01Title\x1fTest",
        url="http://example.com/feed\x0c.xml",
        site_link="http://example.com/site\x08",
    )
    db.session.add(feed)
    db.session.commit()

    response = client.get("/api/opml/export")
    assert response.status_code == 200

    xml_content = response.data.decode("utf-8")

    # Assert control characters are stripped
    invalid_chars = ["\x00", "\x07", "\x0b", "\x01", "\x1f", "\x0c", "\x08"]
    for char in invalid_chars:
        assert char not in xml_content

    # Assert sanitized text is present
    assert 'text="TabNameWithControl"' in xml_content or 'title="TabNameWithControl"' in xml_content
    assert 'text="FeedTitleTest"' in xml_content or 'title="FeedTitleTest"' in xml_content
    assert 'xmlUrl="http://example.com/feed.xml"' in xml_content
    assert 'htmlUrl="http://example.com/site"' in xml_content

    # Verify that the output XML is valid and parseable
    root = ET.fromstring(xml_content)
    assert root.tag == "opml"
