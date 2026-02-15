import io
import logging

from backend.app import app
from backend.models import Feed, Tab

logger = logging.getLogger(__name__)


def test_import(client, mocker):
    """Test the OPML import endpoint using the Flask test client."""
    url = "/api/opml/import"
    logger.info("Testing OPML import at: %s", url)

    # Use an in-memory file object
    opml_content = b'<opml version="1.0"><body><outline text="Test Feed" xmlUrl="http://example.com/feed" /></body></opml>'
    opml_file = io.BytesIO(opml_content)

    data = {"file": (opml_file, "test_feeds.opml")}

    # Mock the internal fetch_and_update_feed to avoid actual network calls
    mocker.patch("backend.feed_service.fetch_and_update_feed")

    response = client.post(url, data=data, content_type="multipart/form-data")

    logger.info("Status Code: %s", response.status_code)
    assert response.status_code == 200

    response_data = response.get_json()
    logger.info("Response: %s", response_data)

    assert response_data.get("imported_count", 0) == 1
    assert response_data.get("skipped_count", 0) == 0

    # Verify DB state
    with app.app_context():
        feed = Feed.query.filter_by(url="http://example.com/feed").first()
        assert feed is not None
        assert feed.name == "Test Feed"

    logger.info("Test PASSED")


def test_import_nested_opml(client, mocker):
    """Test importing an OPML with nested folders."""
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
    <opml version="1.0">
        <head>
            <title>Nested Feeds</title>
        </head>
        <body>
            <outline text="Tech Folder">
                <outline text="Hacker News" xmlUrl="https://news.ycombinator.com/rss"/>
                <outline text="Sub Tech Folder">
                     <outline text="Lobsters" xmlUrl="https://lobste.rs/rss"/>
                </outline>
            </outline>
            <outline text="Root Feed" xmlUrl="https://root.example.com/rss"/>
        </body>
    </opml>
    """

    # Mock network calls to avoid actual fetching
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    # Mock URL validation to ensure feeds are accepted
    mocker.patch(
        "backend.feed_service.validate_and_resolve_url",
        return_value=("127.0.0.1", "example.com"),
    )
    # Mock _validate_xml_safety to always return True for test content
    mocker.patch("backend.feed_service._validate_xml_safety",
                 return_value=True)

    data = {"file": (io.BytesIO(opml_content), "nested.opml")}
    response = client.post("/api/opml/import",
                           data=data,
                           content_type="multipart/form-data")

    assert response.status_code == 200
    result = response.get_json()
    assert result["imported_count"] == 3

    with app.app_context():
        # Check tabs
        tech_tab = Tab.query.filter_by(name="Tech Folder").first()
        assert tech_tab is not None

        sub_tech_tab = Tab.query.filter_by(name="Sub Tech Folder").first()
        assert sub_tech_tab is not None

        # Check feeds
        hn_feed = Feed.query.filter_by(
            url="https://news.ycombinator.com/rss").first()
        assert hn_feed.tab_id == tech_tab.id

        lobsters_feed = Feed.query.filter_by(
            url="https://lobste.rs/rss").first()
        assert lobsters_feed.tab_id == sub_tech_tab.id

        root_feed = Feed.query.filter_by(
            url="https://root.example.com/rss").first()
        # Root feed should be in the default import tab or top level tab
        assert root_feed.tab_id == result["tab_id"]
