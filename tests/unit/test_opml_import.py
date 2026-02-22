import io
import logging
from sqlalchemy import func
from backend.app import app
from backend.models import Feed, Tab, Subscription, db, User

logger = logging.getLogger(__name__)

def test_import(client, mocker):
    """Test the OPML import endpoint."""
    url = "/api/opml/import"
    opml_content = b'<opml version="1.0"><body><outline text="Test Feed" xmlUrl="http://example.com/feed" /></body></opml>'
    data = {"file": (io.BytesIO(opml_content), "test_feeds.opml")}
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    response = client.post(url, data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    response_data = response.get_json()
    assert response_data.get("imported_count", 0) == 1
    with app.app_context():
        feed = Feed.query.filter_by(url="http://example.com/feed").first()
        assert feed is not None
        assert feed.name == "Test Feed"
        assert Subscription.query.filter_by(feed_id=feed.id).count() == 1

def test_import_nested_opml(client, mocker):
    """Test importing an OPML with nested folders."""
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
    <opml version="1.0">
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
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    mocker.patch("backend.feed_service.validate_and_resolve_url", return_value=("127.0.0.1", "example.com"))
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    data = {"file": (io.BytesIO(opml_content), "nested.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    result = response.get_json()
    assert result["imported_count"] == 3
    with app.app_context():
        user = User.query.first()
        tech_tab = Tab.query.filter_by(user_id=user.id, name="Tech Folder").first()
        assert tech_tab is not None
        sub_tech_tab = Tab.query.filter_by(user_id=user.id, name="Sub Tech Folder").first()
        assert sub_tech_tab is not None
        hn_feed = Feed.query.filter_by(url="https://news.ycombinator.com/rss").first()
        assert Subscription.query.filter_by(user_id=user.id, feed_id=hn_feed.id, tab_id=tech_tab.id).first() is not None

def test_opml_import_skips_skipped_folder_types(client, mocker):
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
</opml>""".encode("utf-8")
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    data = {"file": (io.BytesIO(opml_content), "skipped_folder.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    result = response.get_json()
    assert result["imported_count"] == 1
    with app.app_context():
        user = User.query.first()
        skipped_tab = Tab.query.filter_by(user_id=user.id, name="Skipped Folder").first()
        assert skipped_tab is None or not skipped_tab.subscriptions

def test_opml_import_skips_invalid_feed_urls(client, mocker):
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Invalid Feeds Folder">
      <outline text="Invalid Scheme" type="rss" xmlUrl="ftp://example.com/feed.xml" />
    </outline>
  </body>
</opml>"""
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    mocker.patch("backend.feed_service.is_valid_feed_url", return_value=False)
    data = {"file": (io.BytesIO(opml_content), "invalid_urls.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["imported_count"] == 0

def test_opml_import_skips_duplicate_feed_urls(client, mocker):
    with app.app_context():
        user = User.query.first()
        base_tab = Tab(user_id=user.id, name="Existing Tab")
        db.session.add(base_tab)
        db.session.flush()
        existing_feed = Feed(name="Existing Feed", url="https://example.com/existing.xml")
        db.session.add(existing_feed)
        db.session.flush()
        sub = Subscription(user_id=user.id, tab_id=base_tab.id, feed_id=existing_feed.id)
        db.session.add(sub)
        db.session.commit()
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Duplicates Folder">
      <outline text="Existing Feed Duplicate" type="rss" xmlUrl="https://example.com/existing.xml" />
      <outline text="New Feed" type="rss" xmlUrl="https://example.com/new.xml" />
    </outline>
  </body>
</opml>"""
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    mocker.patch("backend.feed_service.is_valid_feed_url", return_value=True)
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    data = {"file": (io.BytesIO(opml_content), "duplicates.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["imported_count"] == 1

def test_opml_import_folder_only_no_outlines(client, mocker):
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <body>
    <outline text="Top Folder"><outline text="Sub Folder" /></outline>
  </body>
</opml>"""
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    data = {"file": (io.BytesIO(opml_content), "folders_only.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["imported_count"] == 0

def test_opml_import_no_outline_elements(client, mocker):
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0"><body></body></opml>"""
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    data = {"file": (io.BytesIO(opml_content), "no_outlines.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.get_json()["imported_count"] == 0

def test_opml_import_anonymous_folder_with_feeds(client, mocker):
    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
    <opml version="1.0">
        <body>
            <outline>
                <outline text="Feed A" xmlUrl="https://example.com/a.xml" />
            </outline>
        </body>
    </opml>"""
    mocker.patch("backend.feed_service._validate_xml_safety", return_value=True)
    mocker.patch("backend.feed_service.fetch_and_update_feed")
    mocker.patch("backend.feed_service.validate_and_resolve_url", return_value=("127.0.0.1", "example.com"))
    data = {"file": (io.BytesIO(opml_content), "anonymous.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    with app.app_context():
        feed = Feed.query.filter_by(url="https://example.com/a.xml").first()
        assert feed is not None
        assert Subscription.query.filter_by(feed_id=feed.id).count() == 1

def test_import_malformed_opml(client):
    malformed_opml = b"<?xml version='1.0'?><opml><body><outline>"
    data = {"file": (io.BytesIO(malformed_opml), "malformed.opml")}
    response = client.post("/api/opml/import", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
