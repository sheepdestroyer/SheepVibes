"""Unit tests for canonical feed name derivation and cleaning."""

import pytest
from backend.feed_name_utils import derive_canonical_feed_name, _extract_domain, _format_domain_as_name


@pytest.mark.parametrize(
    "raw_title,site_url,feed_url,expected",
    [
        # Wccftech tagline override
        (
            "GPU News, CPU News, Reviews & PC Hardware Guides",
            "https://wccftech.com/",
            "https://wccftech.com/feed/",
            "Wccftech",
        ),
        # Wccftech hardware feed (topic sub-feed)
        (
            "Hardware News - Graphics Card & Processor News",
            "https://wccftech.com/topic/hardware/",
            "https://wccftech.com/topic/hardware/feed/",
            "Hardware News",
        ),
        # The Register with domain prefix and suffix
        (
            "www.theregister.com - Articles",
            "https://www.theregister.com/",
            "https://www.theregister.com/headlines.atom",
            "The Register",
        ),
        (
            "The Register",
            "https://www.theregister.com/",
            "https://www.theregister.com/headlines.atom",
            "The Register",
        ),
        # Ars Technica suffix removal
        (
            "Ars Technica - All content",
            "https://arstechnica.com",
            "http://feeds.arstechnica.com/arstechnica/index",
            "Ars Technica",
        ),
        # Tom's Hardware prefix removal
        (
            "Latest from Tom's Hardware",
            "https://www.tomshardware.com",
            "https://www.tomshardware.com/feeds/all",
            "Tom's Hardware",
        ),
        # MIT Technology Review delimiter handling
        (
            "Artificial intelligence – MIT Technology Review",
            "https://www.technologyreview.com",
            "https://www.technologyreview.com/topic/artificial-intelligence/comments/feed/",
            "MIT Technology Review",
        ),
        # Le Monde tagline
        (
            "Le Monde.fr - Actualités et Infos en France et dans le monde",
            "https://www.lemonde.fr",
            "http://www.lemonde.fr/rss/une.xml",
            "Le Monde",
        ),
        # DistroWatch
        (
            "DistroWatch.com: News",
            "http://distrowatch.com",
            "http://distrowatch.com/news/dw.xml",
            "DistroWatch",
        ),
        # Hacker News & Lobsters
        (
            "Hacker News",
            "https://news.ycombinator.com/",
            "https://news.ycombinator.com/rss",
            "Hacker News",
        ),
        (
            "Lobsters",
            "https://lobste.rs/",
            "https://lobste.rs/rss",
            "Lobsters",
        ),
        # Phoronix
        (
            "Phoronix",
            "https://www.phoronix.com/",
            "https://www.phoronix.com/rss.php",
            "Phoronix",
        ),
        # Fallback to domain when raw_title is None
        (
            None,
            None,
            "https://wccftech.com/feed/",
            "Wccftech",
        ),
        (
            None,
            None,
            "https://example.com/rss.xml",
            "Example",
        ),
        # Custom user name preserved
        (
            "My Favorite Tech Blog",
            "https://example.com",
            "https://example.com/rss",
            "My Favorite Tech Blog",
        ),
        # Trailing delimiters stripped
        (
            "Custom Tech News - ",
            "https://example.com",
            "https://example.com/rss",
            "Custom Tech News",
        ),
        (
            "Another Blog | ",
            "https://example.com",
            "https://example.com/rss",
            "Another Blog",
        ),
        # Non-string input safety
        (
            12345,
            None,
            "https://example.com/rss",
            "Example",
        ),
    ],
)
def test_derive_canonical_feed_name(raw_title, site_url, feed_url, expected):
    result = derive_canonical_feed_name(raw_title, site_url=site_url, feed_url=feed_url)
    assert result == expected


def test_extract_domain():
    assert _extract_domain("https://www.theregister.com/headlines.atom") == "theregister.com"
    assert _extract_domain("http://feeds.arstechnica.com/arstechnica/index") == "feeds.arstechnica.com"
    assert _extract_domain("http://localhost:5001/feed") == "localhost"
    assert _extract_domain("") is None
    assert _extract_domain(None) is None


def test_format_domain_as_name():
    assert _format_domain_as_name("example.com") == "Example"
    assert _format_domain_as_name("mysite.org") == "Mysite"
    assert _format_domain_as_name("") == ""
