"""Unit tests for tab management, feed ordering, and cross-tab feed movements."""

import pytest
from backend.app import db
from backend.models import Feed, Tab, User


def create_user_and_login(client, username="alice", password="Password123!"):
    """Helper to create a user and log in via the test client."""
    user = User(username=username, role="user")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return user


def test_get_feeds_for_tab_returns_ordered_feeds(client):
    """Verifies that get_feeds_for_tab returns feeds sorted by Feed.order ascending."""
    user = User.query.filter_by(username="test_default_user").first()
    tab = Tab(name="News", user_id=user.id, order=0)
    db.session.add(tab)
    db.session.commit()

    feed_c = Feed(name="Feed C", url="https://c.example.com/rss", tab_id=tab.id, order=2)
    feed_a = Feed(name="Feed A", url="https://a.example.com/rss", tab_id=tab.id, order=0)
    feed_b = Feed(name="Feed B", url="https://b.example.com/rss", tab_id=tab.id, order=1)
    db.session.add_all([feed_c, feed_a, feed_b])
    db.session.commit()

    resp = client.get(f"/api/tabs/{tab.id}/feeds")
    assert resp.status_code == 200
    data = resp.json
    assert len(data) == 3
    assert [f["name"] for f in data] == ["Feed A", "Feed B", "Feed C"]
    assert [f["order"] for f in data] == [0, 1, 2]


def test_reorder_feeds_in_tab_success(client):
    """Verifies PUT /api/tabs/<tab_id>/feeds/reorder updates feed order successfully."""
    user = User.query.filter_by(username="test_default_user").first()
    tab = Tab(name="Tech", user_id=user.id, order=0)
    db.session.add(tab)
    db.session.commit()

    f1 = Feed(name="Feed 1", url="https://1.example.com/rss", tab_id=tab.id, order=0)
    f2 = Feed(name="Feed 2", url="https://2.example.com/rss", tab_id=tab.id, order=1)
    f3 = Feed(name="Feed 3", url="https://3.example.com/rss", tab_id=tab.id, order=2)
    db.session.add_all([f1, f2, f3])
    db.session.commit()

    # Reverse the order
    resp = client.put(
        f"/api/tabs/{tab.id}/feeds/reorder",
        json={"feed_ids": [f3.id, f1.id, f2.id]},
    )
    assert resp.status_code == 200
    assert resp.json["message"] == "Feeds reordered successfully"

    # Invalidate cache was triggered, verify new order from GET
    get_resp = client.get(f"/api/tabs/{tab.id}/feeds")
    assert get_resp.status_code == 200
    assert [f["id"] for f in get_resp.json] == [f3.id, f1.id, f2.id]
    assert [f["order"] for f in get_resp.json] == [0, 1, 2]


def test_reorder_feeds_validation_errors(client):
    """Verifies validation errors for reordering feeds in a tab."""
    user = User.query.filter_by(username="test_default_user").first()
    tab = Tab(name="Reading", user_id=user.id, order=0)
    db.session.add(tab)
    db.session.commit()

    f1 = Feed(name="Feed 1", url="https://1.example.com/rss", tab_id=tab.id, order=0)
    db.session.add(f1)
    db.session.commit()

    # Non-existent tab
    resp = client.put("/api/tabs/99999/feeds/reorder", json={"feed_ids": [f1.id]})
    assert resp.status_code == 404

    # Missing payload
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={})
    assert resp.status_code == 400

    # Non-list feed_ids
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={"feed_ids": "not-a-list"})
    assert resp.status_code == 400

    # Non-integer in list
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={"feed_ids": ["string-id"]})
    assert resp.status_code == 400

    # Duplicate IDs
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={"feed_ids": [f1.id, f1.id]})
    assert resp.status_code == 400

    # Feed ID not in tab
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={"feed_ids": [99999]})
    assert resp.status_code == 400

    # Empty list succeeds gracefully
    resp = client.put(f"/api/tabs/{tab.id}/feeds/reorder", json={"feed_ids": []})
    assert resp.status_code == 200


def test_reorder_feeds_tenant_isolation(client):
    """Verifies that a user cannot reorder feeds in a tab owned by another user."""
    client.post("/api/auth/logout")
    user_a = create_user_and_login(client, username="alice_reorder")
    tab_a = Tab(name="Alice Tab", user_id=user_a.id, order=0)
    db.session.add(tab_a)
    db.session.commit()

    feed_a = Feed(name="Feed A", url="https://a.example.com/rss", tab_id=tab_a.id, order=0)
    db.session.add(feed_a)
    db.session.commit()

    # Switch to User B
    client.post("/api/auth/logout")
    create_user_and_login(client, username="bob_reorder")

    # Bob attempts to reorder Alice's tab feeds -> 404 Tab not found
    resp = client.put(f"/api/tabs/{tab_a.id}/feeds/reorder", json={"feed_ids": [feed_a.id]})
    assert resp.status_code == 404


def test_move_feed_cross_tab_success(client):
    """Verifies moving a feed from one tab to another and updating positions."""
    user = User.query.filter_by(username="test_default_user").first()
    tab1 = Tab(name="Tab 1", user_id=user.id, order=0)
    tab2 = Tab(name="Tab 2", user_id=user.id, order=1)
    db.session.add_all([tab1, tab2])
    db.session.commit()

    f1 = Feed(name="Feed 1", url="https://1.example.com/rss", tab_id=tab1.id, order=0)
    f2 = Feed(name="Feed 2", url="https://2.example.com/rss", tab_id=tab1.id, order=1)
    f3 = Feed(name="Feed 3", url="https://3.example.com/rss", tab_id=tab2.id, order=0)
    f4 = Feed(name="Feed 4", url="https://4.example.com/rss", tab_id=tab2.id, order=1)
    db.session.add_all([f1, f2, f3, f4])
    db.session.commit()

    # Move f1 to tab2 at position 1 (between f3 and f4)
    resp = client.put(
        f"/api/feeds/{f1.id}/move",
        json={"tab_id": tab2.id, "position": 1},
    )
    assert resp.status_code == 200
    assert resp.json["tab_id"] == tab2.id
    assert resp.json["order"] == 1

    # Verify Tab 1 remaining feeds
    tab1_feeds = client.get(f"/api/tabs/{tab1.id}/feeds").json
    assert len(tab1_feeds) == 1
    assert tab1_feeds[0]["id"] == f2.id
    assert tab1_feeds[0]["order"] == 0

    # Verify Tab 2 feeds order: f3 (order 0), f1 (order 1), f4 (order 2)
    tab2_feeds = client.get(f"/api/tabs/{tab2.id}/feeds").json
    assert len(tab2_feeds) == 3
    assert [f["id"] for f in tab2_feeds] == [f3.id, f1.id, f4.id]
    assert [f["order"] for f in tab2_feeds] == [0, 1, 2]


def test_move_feed_within_same_tab(client):
    """Verifies moving a feed within the same tab to re-position it."""
    user = User.query.filter_by(username="test_default_user").first()
    tab = Tab(name="Same Tab", user_id=user.id, order=0)
    db.session.add(tab)
    db.session.commit()

    f1 = Feed(name="Feed 1", url="https://1.example.com/rss", tab_id=tab.id, order=0)
    f2 = Feed(name="Feed 2", url="https://2.example.com/rss", tab_id=tab.id, order=1)
    f3 = Feed(name="Feed 3", url="https://3.example.com/rss", tab_id=tab.id, order=2)
    db.session.add_all([f1, f2, f3])
    db.session.commit()

    # Move f1 to position 2 (to the end)
    resp = client.put(
        f"/api/feeds/{f1.id}/move",
        json={"tab_id": tab.id, "position": 2},
    )
    assert resp.status_code == 200
    tab_feeds = client.get(f"/api/tabs/{tab.id}/feeds").json
    assert [f["id"] for f in tab_feeds] == [f2.id, f3.id, f1.id]


def test_move_feed_validation_and_errors(client):
    """Verifies error handling on move_feed."""
    user = User.query.filter_by(username="test_default_user").first()
    tab = Tab(name="Valid Tab", user_id=user.id, order=0)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="Valid Feed", url="https://valid.example.com/rss", tab_id=tab.id, order=0)
    db.session.add(feed)
    db.session.commit()

    # Non-existent feed
    resp = client.put("/api/feeds/99999/move", json={"tab_id": tab.id})
    assert resp.status_code == 404

    # Missing tab_id
    resp = client.put(f"/api/feeds/{feed.id}/move", json={})
    assert resp.status_code == 400

    # Non-integer tab_id
    resp = client.put(f"/api/feeds/{feed.id}/move", json={"tab_id": "invalid"})
    assert resp.status_code == 400

    # Non-existent target tab
    resp = client.put(f"/api/feeds/{feed.id}/move", json={"tab_id": 99999})
    assert resp.status_code == 404

    # Invalid position type
    resp = client.put(f"/api/feeds/{feed.id}/move", json={"tab_id": tab.id, "position": "bad"})
    assert resp.status_code == 400


def test_move_feed_tenant_isolation(client):
    """Verifies that a user cannot move another user's feed, or move their own feed to another user's tab."""
    client.post("/api/auth/logout")
    user_a = create_user_and_login(client, username="alice_move")
    tab_a = Tab(name="Alice Tab", user_id=user_a.id, order=0)
    db.session.add(tab_a)
    db.session.commit()

    feed_a = Feed(name="Alice Feed", url="https://alice.example.com/rss", tab_id=tab_a.id, order=0)
    db.session.add(feed_a)
    db.session.commit()

    # Switch to User B
    client.post("/api/auth/logout")
    user_b = create_user_and_login(client, username="bob_move")
    tab_b = Tab(name="Bob Tab", user_id=user_b.id, order=0)
    db.session.add(tab_b)
    db.session.commit()

    feed_b = Feed(name="Bob Feed", url="https://bob.example.com/rss", tab_id=tab_b.id, order=0)
    db.session.add(feed_b)
    db.session.commit()

    # Bob attempts to move Alice's feed -> 404
    resp = client.put(f"/api/feeds/{feed_a.id}/move", json={"tab_id": tab_b.id})
    assert resp.status_code == 404

    # Bob attempts to move his feed into Alice's tab -> 404 Target tab not found
    resp = client.put(f"/api/feeds/{feed_b.id}/move", json={"tab_id": tab_a.id})
    assert resp.status_code == 404
