import socket
from unittest.mock import MagicMock

import pytest

from . import feed_service

# Mock XXE payload
XXE_PAYLOAD = b"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""

# Mock Billion Laughs payload
BILLION_LAUGHS_PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

JSON_PAYLOAD = b"""{
    "version": "https://jsonfeed.org/version/1",
    "title": "My Example Feed",
    "home_page_url": "https://example.org/",
    "feed_url": "https://example.org/feed.json",
    "items": []
}"""

VALID_RSS_PAYLOAD = b"""<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
 <title>RSS Title</title>
 <description>This is an example of an RSS feed</description>
 <link>http://www.example.com/main.html</link>
 <item>
  <title>Item 1</title>
  <link>http://www.example.com/item1.html</link>
 </item>
</channel>
</rss>"""


@pytest.fixture
def mock_network(mocker):
    # Mock socket.getaddrinfo to avoid DNS lookup / SSRF check failures
    mock_getaddrinfo = mocker.patch("backend.feed_service.socket.getaddrinfo")
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6,
                                      "", ("93.184.216.34", 80))]
    return mock_getaddrinfo


def test_xxe_rejection(mocker, mock_network):
    # Mock urllib to return XXE payload
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")
    mock_response = MagicMock()
    mock_response.read.return_value = XXE_PAYLOAD
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock feedparser to avoid actual parsing errors, we want to test if it reaches here
    mocker.patch("backend.feed_service.feedparser.parse",
                 return_value=MagicMock())

    # Call fetch_feed
    result = feed_service.fetch_feed("http://example.com/feed")

    # Expect None due to security violation
    assert result is None


def test_billion_laughs_rejection(mocker, mock_network):
    # Mock urllib to return Billion Laughs payload
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")
    mock_response = MagicMock()
    mock_response.read.return_value = BILLION_LAUGHS_PAYLOAD
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock feedparser to avoid actual parsing errors
    mocker.patch("backend.feed_service.feedparser.parse",
                 return_value=MagicMock())

    # Call fetch_feed
    result = feed_service.fetch_feed("http://example.com/feed")

    # Expect None due to security violation
    assert result is None


def test_json_pass_through(mocker, mock_network):
    # Mock urllib to return JSON
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")
    mock_response = MagicMock()
    mock_response.read.return_value = JSON_PAYLOAD
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock feedparser to return a success object
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0
    mocker.patch("backend.feed_service.feedparser.parse",
                 return_value=mock_parsed_feed)

    # Call fetch_feed
    result = feed_service.fetch_feed("http://example.com/feed")

    # Expect result (validation failed syntax, but passed to feedparser)
    assert result == mock_parsed_feed


def test_valid_rss_pass_through(mocker, mock_network):
    # Mock urllib to return valid RSS
    mock_urlopen = mocker.patch("backend.feed_service.urllib.request.urlopen")
    mock_response = MagicMock()
    mock_response.read.return_value = VALID_RSS_PAYLOAD
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock feedparser
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0
    mocker.patch("backend.feed_service.feedparser.parse",
                 return_value=mock_parsed_feed)

    # Call fetch_feed
    result = feed_service.fetch_feed("http://example.com/feed")

    # Expect result (validation passed or ignored)
    assert result == mock_parsed_feed
