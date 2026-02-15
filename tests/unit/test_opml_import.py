import io
import logging

from backend.app import app
from backend.models import Feed, Tab, db
from sqlalchemy import func

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
    assert result["skipped_count"] == 0

    with app.app_context():
        # Check tabs
        tech_tab = Tab.query.filter_by(name="Tech Folder").first()
        assert tech_tab is not None

        sub_tech_tab = Tab.query.filter_by(name="Sub Tech Folder").first()
        assert sub_tech_tab is not None

        # Verify affected_tab_ids
        assert {tech_tab.id, sub_tech_tab.id, result["tab_id"]}.issubset(
            set(result["affected_tab_ids"]))

        # Check feeds
        hn_feed = Feed.query.filter_by(
            url="https://news.ycombinator.com/rss").first()
        assert hn_feed is not None
        assert hn_feed.tab_id == tech_tab.id

        lobsters_feed = Feed.query.filter_by(
            url="https://lobste.rs/rss").first()
        assert lobsters_feed is not None
        assert lobsters_feed.tab_id == sub_tech_tab.id

        root_feed = Feed.query.filter_by(
            url="https://root.example.com/rss").first()
        assert root_feed is not None
        # Root feed should be in the default import tab or top level tab
        assert root_feed.tab_id == result["tab_id"]


def test_opml_import_skips_skipped_folder_types(client, mocker):
    """Test that folders with types in SKIPPED_FOLDER_TYPES are skipped."""
    from backend.feed_service import SKIPPED_FOLDER_TYPES

    skipped_type = next(iter(SKIPPED_FOLDER_TYPES))

    opml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Skipped Folder" title="Skipped Folder" type="{skipped_type}">
      <outline text="Should Not Import" type="rss" xmlUrl="https://example.com/should-not-import.xml" />
    </outline>
    <outline text="Valid Folder">
      <outline text="Valid Feed" type="rss" xmlUrl="https://example.com/valid.xml" />
    </outline>
  </body>
</opml>
""".encode("utf-8")

    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    mocker.patch("backend.feed_service.fetch_and_update_feed")

    data = {"file": (io.BytesIO(opml_content), "skipped_folder.opml")}
    response = client.post(
        "/api/opml/import",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()

    # Only the feed under "Valid Folder" should be imported.
    assert result["imported_count"] == 1
    # The subtree under the skipped folder should be counted as skipped.
    assert result["skipped_count"] >= 1


def test_opml_import_skips_invalid_feed_urls(client, mocker):
    """Test that feeds with invalid URLs are skipped."""
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Invalid Feeds Folder">
      <outline text="Invalid Scheme" type="rss" xmlUrl="ftp://example.com/feed.xml" />
      <outline text="Malformed URL" type="rss" xmlUrl="not-a-url" />
    </outline>
  </body>
</opml>
"""

    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    # Ensure feeds are treated as invalid regardless of the specific URL-checking logic.
    mocker.patch("backend.feed_service.is_valid_feed_url", return_value=False)

    data = {"file": (io.BytesIO(opml_content), "invalid_urls.opml")}
    response = client.post(
        "/api/opml/import",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()

    # No feeds should be imported; all should be skipped.
    assert result["imported_count"] == 0
    assert result["skipped_count"] == 2


def test_opml_import_skips_duplicate_feed_urls(client, mocker):
    """Test that duplicate feed URLs are skipped."""
    with app.app_context():
        base_tab = Tab(name="Existing Tab")
        db.session.add(base_tab)
        db.session.flush()

        existing_feed = Feed(
            name="Existing Feed",
            url="https://example.com/existing.xml",
            tab_id=base_tab.id,
        )
        db.session.add(existing_feed)
        db.session.commit()

    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Duplicates Folder">
      <!-- Duplicate of existing DB feed -->
      <outline text="Existing Feed Duplicate" type="rss" xmlUrl="https://example.com/existing.xml" />
      <!-- First occurrence of new feed -->
      <outline text="New Feed" type="rss" xmlUrl="https://example.com/new.xml" />
      <!-- Duplicate of new feed within the same OPML -->
      <outline text="New Feed Duplicate" type="rss" xmlUrl="https://example.com/new.xml" />
    </outline>
  </body>
</opml>
"""

    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    # Let URL validation pass so duplicates are the only reason for skipping.
    mocker.patch("backend.feed_service.is_valid_feed_url", return_value=True)
    mocker.patch("backend.feed_service.fetch_and_update_feed")

    data = {"file": (io.BytesIO(opml_content), "duplicates.opml")}
    response = client.post(
        "/api/opml/import",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()

    # Only the first occurrence of the new feed should be imported.
    assert result["imported_count"] == 1
    # One existing-in-DB duplicate + one in-file duplicate should be skipped.
    assert result["skipped_count"] == 2

    with app.app_context():
        # Confirm that we still only have one feed per URL overall.
        feeds_by_url = (
            Feed.query.with_entities(Feed.url, func.count(Feed.id))
            .group_by(Feed.url)
            .all()
        )

        counts = {url: count for url, count in feeds_by_url}
        assert counts["https://example.com/existing.xml"] == 1
        assert counts["https://example.com/new.xml"] == 1


def test_opml_import_folder_only_no_outlines(client, mocker):
    """Test importing an OPML with only folders and no feeds."""
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Top Folder">
      <outline text="Sub Folder" />
    </outline>
  </body>
</opml>
"""

    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)

    data = {"file": (io.BytesIO(opml_content), "folders_only.opml")}
    response = client.post(
        "/api/opml/import",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()

    # No feeds to import or skip; should trigger the "No <outline> elements..." path.
    assert result["imported_count"] == 0
    # Empty folders are counted as skipped
    assert result["skipped_count"] == 1


def test_opml_import_no_outline_elements(client, mocker):
    """Test importing an OPML with no outline elements at all."""
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
  </body>
</opml>
"""

    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)

    data = {"file": (io.BytesIO(opml_content), "no_outlines.opml")}
    response = client.post(
        "/api/opml/import",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()

    # No outlines present; nothing imported or skipped.
    assert result["imported_count"] == 0
    assert result["skipped_count"] == 0
