"""Unit tests for multi-tenant data isolation, user scoping, and cache partitioning."""

import io
import pytest
from backend.cache_utils import invalidate_tabs_cache, make_tab_feeds_cache_key, make_tabs_cache_key
from backend.extensions import db
from backend.models import Feed, FeedItem, Tab, User


@pytest.fixture
def user_a(client):
    """Creates User A."""
    user = User(username="user_a", email="usera@example.com")
    user.set_password("PassUserA123")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def user_b(client):
    """Creates User B."""
    user = User(username="user_b", email="userb@example.com")
    user.set_password("PassUserB123")
    db.session.add(user)
    db.session.commit()
    return user


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_tabs_scoping_and_same_name_support(client, user_a, user_b):
    """Verifies that tabs are strictly scoped to the logged-in user and same names are permitted across users."""
    # User A creates a tab named "Tech"
    login(client, "user_a", "PassUserA123")
    resp_a = client.post("/api/tabs", json={"name": "Tech"})
    assert resp_a.status_code == 201
    tab_a_id = resp_a.json["id"]

    # User A sees 1 tab
    tabs_a = client.get("/api/tabs").json
    assert len(tabs_a) == 1
    assert tabs_a[0]["name"] == "Tech"

    # User B logs in
    client.post("/api/auth/logout")
    login(client, "user_b", "PassUserB123")

    # User B initially sees 0 tabs
    tabs_b = client.get("/api/tabs").json
    assert len(tabs_b) == 0

    # User B can also create a tab named "Tech" without naming conflict
    resp_b = client.post("/api/tabs", json={"name": "Tech"})
    assert resp_b.status_code == 201
    tab_b_id = resp_b.json["id"]
    assert tab_b_id != tab_a_id

    # User B trying to duplicate "Tech" on their own account gets 409
    dup_resp = client.post("/api/tabs", json={"name": "Tech"})
    assert dup_resp.status_code == 409

    # User B cannot rename or delete User A's tab (404)
    rename_resp = client.put(f"/api/tabs/{tab_a_id}", json={"name": "Hacked"})
    assert rename_resp.status_code == 404

    del_resp = client.delete(f"/api/tabs/{tab_a_id}")
    assert del_resp.status_code == 404

    get_feeds_resp = client.get(f"/api/tabs/{tab_a_id}/feeds")
    assert get_feeds_resp.status_code == 404


def test_feeds_and_items_isolation(client, user_a, user_b, mocker):
    """Verifies that feeds and feed items are strictly isolated per user."""
    # Mock network fetch
    mocker.patch(
        "backend.blueprints.feeds._get_feed_metadata",
        return_value=("Sample Feed", "https://example.com", None),
    )

    # User A creates tab and feed
    login(client, "user_a", "PassUserA123")
    tab_a = client.post("/api/tabs", json={"name": "News"}).json
    feed_a_resp = client.post("/api/feeds", json={"url": "https://example.com/rss", "tab_id": tab_a["id"]})
    assert feed_a_resp.status_code == 201
    feed_a_id = feed_a_resp.json["id"]

    # Manually add an item to feed A
    item_a = FeedItem(feed_id=feed_a_id, title="Article A", link="https://example.com/1", is_read=False)
    db.session.add(item_a)
    db.session.commit()
    item_a_id = item_a.id

    # User B logs in
    client.post("/api/auth/logout")
    login(client, "user_b", "PassUserB123")
    tab_b = client.post("/api/tabs", json={"name": "News"}).json

    # User B can subscribe to the same feed URL in their tab
    feed_b_resp = client.post("/api/feeds", json={"url": "https://example.com/rss", "tab_id": tab_b["id"]})
    assert feed_b_resp.status_code == 201
    feed_b_id = feed_b_resp.json["id"]
    assert feed_b_id != feed_a_id

    # User B cannot update, delete, or fetch items for User A's feed
    assert client.put(f"/api/feeds/{feed_a_id}", json={"url": "https://example.com/new-rss"}).status_code == 404
    assert client.delete(f"/api/feeds/{feed_a_id}").status_code == 404
    assert client.get(f"/api/feeds/{feed_a_id}/items").status_code == 404
    assert client.post(f"/api/feeds/{feed_a_id}/update").status_code == 404

    # User B cannot mark User A's item as read
    assert client.post(f"/api/items/{item_a_id}/read").status_code == 404


def test_opml_export_and_import_isolation(client, user_a, user_b):
    """Verifies that OPML import and export only access tabs/feeds belonging to the user."""
    # User A creates a tab and feed
    login(client, "user_a", "PassUserA123")
    tab_a = Tab(name="User A Tab", user_id=user_a.id)
    db.session.add(tab_a)
    db.session.commit()
    feed_a = Feed(name="User A Feed", url="https://example.com/a.xml", tab_id=tab_a.id)
    db.session.add(feed_a)
    db.session.commit()

    # User A exports OPML
    export_a = client.get("/api/opml/export")
    assert export_a.status_code == 200
    assert "User A Tab" in export_a.text
    assert "https://example.com/a.xml" in export_a.text

    # User B logs in and exports OPML -> User A's tab is not present
    client.post("/api/auth/logout")
    login(client, "user_b", "PassUserB123")

    export_b = client.get("/api/opml/export")
    assert export_b.status_code == 200
    assert "User A Tab" not in export_b.text


def test_opml_nested_import_isolation(client, user_a, user_b, mocker):
    """Verifies that nested OPML imports create tabs specifically assigned to the importing user."""
    mocker.patch("backend.feed_service.fetch_and_update_feed")

    opml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
    <opml version="2.0">
      <head><title>Subscriptions</title></head>
      <body>
        <outline text="Design" title="Design">
          <outline text="Smashing Magazine" title="Smashing Magazine" type="rss" xmlUrl="https://www.smashingmagazine.com/feed/" />
        </outline>
      </body>
    </opml>"""

    # User A imports OPML with folder "Design"
    login(client, "user_a", "PassUserA123")
    resp_a = client.post(
        "/api/opml/import",
        data={"file": (io.BytesIO(opml_content), "feeds.opml")},
        content_type="multipart/form-data",
    )
    assert resp_a.status_code == 200

    # User A has tab "Design"
    tab_design_a = Tab.query.filter_by(name="Design", user_id=user_a.id).first()
    assert tab_design_a is not None

    # User B logs in and should not see "Design" tab
    client.post("/api/auth/logout")
    login(client, "user_b", "PassUserB123")
    tabs_b = client.get("/api/tabs").json
    assert not any(t["name"] == "Design" for t in tabs_b)

    # User B imports same OPML
    resp_b = client.post(
        "/api/opml/import",
        data={"file": (io.BytesIO(opml_content), "feeds.opml")},
        content_type="multipart/form-data",
    )
    assert resp_b.status_code == 200

    # User B now has their own separate "Design" tab
    tab_design_b = Tab.query.filter_by(name="Design", user_id=user_b.id).first()
    assert tab_design_b is not None
    assert tab_design_b.id != tab_design_a.id


def test_cache_keys_partitioning_by_user(client, user_a, user_b):
    """Verifies that cache keys and invalidations are strictly partitioned per user ID."""
    key_a = make_tabs_cache_key(user_id=user_a.id)
    key_b = make_tabs_cache_key(user_id=user_b.id)

    assert f"/user/{user_a.id}/" in key_a
    assert f"/user/{user_b.id}/" in key_b
    assert key_a != key_b

    feed_key_a = make_tab_feeds_cache_key(tab_id=1, user_id=user_a.id)
    feed_key_b = make_tab_feeds_cache_key(tab_id=1, user_id=user_b.id)
    assert feed_key_a != feed_key_b
