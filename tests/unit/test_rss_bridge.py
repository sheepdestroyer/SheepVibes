#!/usr/bin/env python3
"""
Unit test suite for RSS-Bridge deployment, URL validation, and RSS-less page feed bridging.
"""

import os
from unittest.mock import MagicMock, patch
import pytest

from backend import feed_service
from backend.app import app
from backend.models import Feed, FeedItem, Tab, User, db


SAMPLE_ATOM_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title type="text">Lucebox Blog</title>
  <link rel="alternate" type="text/html" href="https://www.lucebox.com/blog"/>
  <link rel="self" type="application/atom+xml" href="http://localhost:80/?action=display&amp;bridge=LuceboxBridge"/>
  <id>http://localhost:80/?action=display&amp;bridge=LuceboxBridge</id>
  <updated>2026-09-06T10:00:00+00:00</updated>
  <entry>
    <title type="html">Ling 3.0 Flash on DGX Spark: Up to 141.9 tok/s with Adaptive DSpark and FlashKDA</title>
    <published>2026-08-28T00:00:00+00:00</published>
    <updated>2026-08-28T00:00:00+00:00</updated>
    <id>https://www.lucebox.com/blog/ling3-flash-dgx-spark</id>
    <link rel="alternate" type="text/html" href="https://www.lucebox.com/blog/ling3-flash-dgx-spark"/>
    <content type="html">Ling 3.0 Flash on DGX Spark benchmark results</content>
  </entry>
  <entry>
    <title type="html">Qwen3.8-27B on the AMD R9700: up to 227 tok/s</title>
    <published>2026-08-21T00:00:00+00:00</published>
    <updated>2026-08-21T00:00:00+00:00</updated>
    <id>https://www.lucebox.com/blog/qwen38-r9700</id>
    <link rel="alternate" type="text/html" href="https://www.lucebox.com/blog/qwen38-r9700"/>
    <content type="html">Qwen3.8 benchmarks</content>
  </entry>
</feed>
"""

SAMPLE_HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Lucebox Engineering Blog</title>
</head>
<body>
  <h1>Welcome to the blog</h1>
  <p>No RSS link here!</p>
</body>
</html>
"""

SAMPLE_HTML_WITH_ALTERNATE = """<!DOCTYPE html>
<html>
<head>
  <title>Tech Blog</title>
  <link rel="alternate" type="application/rss+xml" title="Tech Feed" href="/feed.xml" />
</head>
<body>
  <h1>Tech Blog</h1>
</body>
</html>
"""


@pytest.fixture
def auth_client():
    """Provides a test client authenticated with an admin user."""
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        user = User(username="testadmin", role="admin", is_active=True)
        user.set_password("AdminPass123!")
        db.session.add(user)
        db.session.commit()

        tab = Tab(user_id=user.id, name="General", order=0)
        db.session.add(tab)
        db.session.commit()

        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = user.id

        yield client, user, tab
        db.session.remove()
        db.drop_all()


def test_get_rss_bridge_url(monkeypatch):
    """Verifies retrieval and normalization of the configured RSS_BRIDGE_URL."""
    monkeypatch.delenv("RSS_BRIDGE_URL", raising=False)
    assert feed_service.get_rss_bridge_url() is None

    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80/")
    assert feed_service.get_rss_bridge_url() == "http://localhost:80"

    monkeypatch.setenv("RSS_BRIDGE_URL", "  http://127.0.0.1:3000/  ")
    assert feed_service.get_rss_bridge_url() == "http://127.0.0.1:3000"


def test_is_rss_bridge_url(monkeypatch):
    """Verifies detection of URLs belonging to the trusted RSS-Bridge service."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")

    assert feed_service.is_rss_bridge_url("http://localhost:80/?action=display&bridge=LuceboxBridge")
    assert feed_service.is_rss_bridge_url("http://127.0.0.1:80/?action=detect&url=foo")
    assert not feed_service.is_rss_bridge_url("http://localhost:8080/?action=detect")
    assert not feed_service.is_rss_bridge_url("http://127.0.0.1:6379/")
    assert not feed_service.is_rss_bridge_url("https://localhost:80/")
    assert not feed_service.is_rss_bridge_url("https://google.com/")
    assert not feed_service.is_rss_bridge_url(None)
    assert not feed_service.is_rss_bridge_url("")


def test_validate_and_resolve_url_allows_configured_rss_bridge(monkeypatch):
    """Verifies validate_and_resolve_url allows configured RSS_BRIDGE_URL while blocking other loopback ports."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")
    monkeypatch.setenv("TESTING", "false")

    # The configured RSS-Bridge URL must be allowed
    safe_ip, host = feed_service.validate_and_resolve_url("http://localhost:80/?action=display")
    assert safe_ip == "127.0.0.1"
    assert host in ("localhost", "127.0.0.1")

    safe_ip, host = feed_service.validate_and_resolve_url("http://127.0.0.1:80/?action=detect")
    assert safe_ip == "127.0.0.1"
    assert host in ("localhost", "127.0.0.1")

    # Another loopback port (e.g. 6379, 5000, 22) must still be blocked as SSRF
    safe_ip, _ = feed_service.validate_and_resolve_url("http://localhost:6379/")
    assert safe_ip is None

    safe_ip, _ = feed_service.validate_and_resolve_url("http://127.0.0.1:22/")
    assert safe_ip is None


def test_discover_feed_url_from_html():
    """Verifies autodiscovery of RSS/Atom feed links in HTML headers."""
    base_url = "https://example.com/blog/"

    # HTML with <link rel="alternate" type="application/rss+xml" href="/feed.xml">
    found = feed_service.discover_feed_url_from_html(SAMPLE_HTML_WITH_ALTERNATE, base_url)
    assert found == "https://example.com/feed.xml"

    # HTML without any feed link
    assert feed_service.discover_feed_url_from_html(SAMPLE_HTML_PAGE, base_url) is None

    # HTML with Atom link
    atom_html = '<html><head><link rel="alternate" type="application/atom+xml" href="atom.xml"></head></html>'
    found_atom = feed_service.discover_feed_url_from_html(atom_html, base_url)
    assert found_atom == "https://example.com/blog/atom.xml"


def test_fetch_rss_bridge_feed_success(monkeypatch):
    """Verifies that fetch_rss_bridge_feed queries RSS-Bridge and parses the generated Atom feed."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")

    mock_response = MagicMock()
    mock_response.getheader.return_value = str(len(SAMPLE_ATOM_FEED))
    mock_response.read.return_value = SAMPLE_ATOM_FEED.encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    with patch.object(feed_service, "_build_safe_opener", return_value=mock_opener):
        parsed = feed_service.fetch_rss_bridge_feed("https://www.lucebox.com/blog")
        assert parsed is not None
        assert parsed.feed.get("title") == "Lucebox Blog"
        assert len(parsed.entries) == 2
        assert parsed.entries[0]["title"] == (
            "Ling 3.0 Flash on DGX Spark: Up to 141.9 tok/s with Adaptive DSpark and FlashKDA"
        )
        assert parsed.entries[0]["link"] == "https://www.lucebox.com/blog/ling3-flash-dgx-spark"


def test_fetch_rss_bridge_feed_not_found(monkeypatch):
    """Verifies that fetch_rss_bridge_feed returns None when RSS-Bridge has no bridge for the URL."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")

    no_bridge_html = "<html><head><title>RSS-Bridge</title></head><body>No bridge found for given URL</body></html>"
    mock_response = MagicMock()
    mock_response.getheader.return_value = str(len(no_bridge_html))
    mock_response.read.return_value = no_bridge_html.encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    with patch.object(feed_service, "_build_safe_opener", return_value=mock_opener):
        parsed = feed_service.fetch_rss_bridge_feed("https://example.com/rss-less-unknown")
        assert parsed is None


def test_fetch_feed_delegates_to_rss_bridge(monkeypatch):
    """Verifies fetch_feed delegates to RSS-Bridge when given an RSS-less page URL."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")

    # First call downloads SAMPLE_HTML_PAGE (0 entries), second call downloads SAMPLE_ATOM_FEED from RSS-Bridge
    def fake_download(opener, url):
        if "action=detect" in url or "bridge=" in url:
            return SAMPLE_ATOM_FEED.encode("utf-8")
        return SAMPLE_HTML_PAGE.encode("utf-8")

    with patch.object(feed_service, "validate_and_resolve_url", return_value=("192.0.2.1", "www.lucebox.com")), \
         patch.object(feed_service, "_build_safe_opener", return_value=MagicMock()), \
         patch.object(feed_service, "_download_feed_content", side_effect=fake_download):

        parsed = feed_service.fetch_feed("https://www.lucebox.com/blog")
        assert parsed is not None
        assert len(parsed.entries) == 2
        assert parsed.feed.get("title") == "Lucebox Blog"
        assert parsed.feed.get("link") == "https://www.lucebox.com/blog"


def test_add_feed_api_creates_rss_bridged_feed(auth_client, monkeypatch):
    """Verifies POST /api/feeds successfully creates and populates an RSS-less page via RSS-Bridge."""
    client, user, tab = auth_client
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")

    def fake_download(opener, url):
        if "action=detect" in url or "bridge=" in url:
            return SAMPLE_ATOM_FEED.encode("utf-8")
        return SAMPLE_HTML_PAGE.encode("utf-8")

    with patch.object(feed_service, "validate_and_resolve_url", return_value=("192.0.2.1", "www.lucebox.com")), \
         patch.object(feed_service, "_build_safe_opener", return_value=MagicMock()), \
         patch.object(feed_service, "_download_feed_content", side_effect=fake_download):

        resp = client.post(
            "/api/feeds",
            json={"url": "https://www.lucebox.com/blog", "tab_id": tab.id},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "Lucebox Blog"
        assert data["url"] == "https://www.lucebox.com/blog"
        assert data["site_link"] == "https://www.lucebox.com/blog"
        assert data["unread_count"] == 2

        # Verify DB records
        feed = Feed.query.filter_by(url="https://www.lucebox.com/blog").first()
        assert feed is not None
        items = FeedItem.query.filter_by(feed_id=feed.id).all()
        assert len(items) == 2
        assert items[0].title.startswith("Ling 3.0 Flash")


def test_antigravity_changelog_feed_parsing(monkeypatch):
    """Verifies RSS-Bridge integration for antigravity.google/changelog."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")
    antigravity_atom = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title type="text">Antigravity Changelog</title>
      <link rel="alternate" type="text/html" href="https://antigravity.google/changelog"/>
      <entry>
        <title type="html">[2.12.2] Gemini 3.8 Flash using ADC in AGY Enterprise</title>
        <published>2026-09-03T00:00:00+00:00</published>
        <id>https://antigravity.google/releases?tab=hub&amp;version=2.12.2</id>
        <link rel="alternate" type="text/html" href="https://antigravity.google/releases?tab=hub&amp;version=2.12.2"/>
        <content type="html">Antigravity 2.12.2 enables enterprise users to access Gemini 3.8 Flash.</content>
      </entry>
    </feed>
    """

    def fake_download(opener, url):
        return antigravity_atom.encode("utf-8")

    with patch.object(feed_service, "validate_and_resolve_url", return_value=("192.0.2.1", "antigravity.google")), \
         patch.object(feed_service, "_build_safe_opener", return_value=MagicMock()), \
         patch.object(feed_service, "_download_feed_content", side_effect=fake_download):

        parsed = feed_service.fetch_feed("https://antigravity.google/changelog")
        assert parsed is not None
        assert parsed.feed.get("title") == "Antigravity Changelog"
        assert len(parsed.entries) == 1
        assert "[2.12.2]" in parsed.entries[0]["title"]


def test_jules_changelog_feed_parsing(monkeypatch):
    """Verifies RSS-Bridge integration for jules.google/docs/changelog/."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")
    jules_atom = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title type="text">Jules Changelog</title>
      <link rel="alternate" type="text/html" href="https://jules.google/docs/changelog/"/>
      <entry>
        <title type="html">Gemini 3.1 Pro is now available in Jules</title>
        <id>https://jules.google/docs/changelog/#gemini-31-pro</id>
        <link rel="alternate" type="text/html"
              href="https://jules.google/docs/changelog/#gemini-31-pro"/>
        <content type="html">Gemini 3.1 Pro is now available in Jules for Google Pro plan users.</content>
      </entry>
    </feed>
    """

    def fake_download(opener, url):
        return jules_atom.encode("utf-8")

    with patch.object(feed_service, "validate_and_resolve_url", return_value=("192.0.2.1", "jules.google")), \
         patch.object(feed_service, "_build_safe_opener", return_value=MagicMock()), \
         patch.object(feed_service, "_download_feed_content", side_effect=fake_download):

        parsed = feed_service.fetch_feed("https://jules.google/docs/changelog/")
        assert parsed is not None
        assert parsed.feed.get("title") == "Jules Changelog"
        assert len(parsed.entries) == 1
        assert "Gemini 3.1 Pro" in parsed.entries[0]["title"]


def test_github_releases_feed_parsing(monkeypatch):
    """Verifies RSS-Bridge integration for github.com/NousResearch/hermes-agent/releases."""
    monkeypatch.setenv("RSS_BRIDGE_URL", "http://localhost:80")
    github_atom = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title type="text">Release notes from NousResearch/hermes-agent</title>
      <link rel="alternate" type="text/html" href="https://github.com/NousResearch/hermes-agent/releases"/>
      <entry>
        <title type="html">Hermes Agent v0.21.0 (v2026.8.31)</title>
        <published>2026-08-31T19:29:49+00:00</published>
        <id>https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.31</id>
        <link rel="alternate" type="text/html"
              href="https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.31"/>
        <content type="html">Hermes Agent v0.21.0 release notes</content>
      </entry>
    </feed>
    """

    def fake_download(opener, url):
        return github_atom.encode("utf-8")

    with patch.object(feed_service, "validate_and_resolve_url", return_value=("192.0.2.1", "github.com")), \
         patch.object(feed_service, "_build_safe_opener", return_value=MagicMock()), \
         patch.object(feed_service, "_download_feed_content", side_effect=fake_download):

        parsed = feed_service.fetch_feed("https://github.com/NousResearch/hermes-agent/releases")
        assert parsed is not None
        assert "NousResearch/hermes-agent" in parsed.feed.get("title")
        assert len(parsed.entries) == 1
        assert "Hermes Agent v0.21.0" in parsed.entries[0]["title"]


def test_deployment_configuration_and_bridge_files():
    """Verifies all required Quadlet definitions, custom bridges, and deployment scripts exist."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    # Quadlet container
    quadlet_file = os.path.join(project_root, "pod", "sheepvibes-rssbridge.container")
    assert os.path.isfile(quadlet_file)
    with open(quadlet_file, "r", encoding="utf-8") as f:
        content = f.read()
        assert "ContainerName=sheepvibes-rssbridge" in content
        assert "docker.io/rssbridge/rss-bridge:latest" in content
        assert "Pod=sheepvibespod.pod" in content

    # Custom bridge files
    bridges_dir = os.path.join(project_root, "pod", "bridges")
    for bridge_name in ("LuceboxBridge.php", "AntigravityChangelogBridge.php", "JulesChangelogBridge.php"):
        bridge_path = os.path.join(bridges_dir, bridge_name)
        assert os.path.isfile(bridge_path)
        with open(bridge_path, "r", encoding="utf-8") as f:
            b_content = f.read()
            assert "extends BridgeAbstract" in b_content
            assert "function collectData()" in b_content
            assert "function detectParameters($url)" in b_content

    # Deploy pod script
    deploy_script = os.path.join(project_root, "scripts", "deploy_pod.sh")
    with open(deploy_script, "r", encoding="utf-8") as f:
        d_content = f.read()
        assert "sheepvibes-rssbridge.container" in d_content
        assert "LuceboxBridge.php" in d_content
        assert "AntigravityChangelogBridge.php" in d_content
        assert "JulesChangelogBridge.php" in d_content

    # Dev manager script
    dev_script = os.path.join(project_root, "scripts", "dev_manager.sh")
    with open(dev_script, "r", encoding="utf-8") as f:
        dev_content = f.read()
        assert "sheepvibes-dev-rssbridge" in dev_content
        assert "RSS_BRIDGE_URL" in dev_content
