import datetime
import io
import json
import os
import xml.etree.ElementTree as ET
from datetime import timezone
from unittest.mock import MagicMock, patch

import pytest

from backend.app import app, cache
from backend.feed_service import (
    parse_published_time,
    process_feed_entries,
)
from backend.models import Feed, FeedItem, Subscription, Tab, User, UserItemState, db

# --- Tests ---


def test_get_tabs_empty(client):
    response = client.get("/api/tabs")
    assert response.status_code == 200
    assert response.json == []


def test_get_tabs_with_data(client):
    user = User.query.first()
    tab1 = Tab(user_id=user.id, name="Tech", order=1)
    tab2 = Tab(user_id=user.id, name="News", order=0)
    db.session.add_all([tab1, tab2])
    db.session.commit()

    response = client.get("/api/tabs")
    assert response.status_code == 200
    data = response.json
    assert len(data) == 2
    # Order is News (0), Tech (1)
    assert data[0]["name"] == "News"
    assert data[1]["name"] == "Tech"


def test_create_tab_success(client):
    response = client.post("/api/tabs", json={"name": "Science"})
    assert response.status_code == 201
    assert response.json["name"] == "Science"
    assert Tab.query.filter_by(name="Science").count() == 1


def test_rename_tab_success(client):
    user = User.query.first()
    tab = Tab(user_id=user.id, name="Old Name")
    db.session.add(tab)
    db.session.commit()
    tab_id = tab.id

    response = client.put(f"/api/tabs/{tab_id}", json={"name": "New Name"})
    assert response.status_code == 200
    assert db.session.get(Tab, tab_id).name == "New Name"


def test_delete_tab_success(client):
    user = User.query.first()
    tab = Tab(user_id=user.id, name="To Delete")
    db.session.add(tab)
    db.session.commit()
    tab_id = tab.id

    response = client.delete(f"/api/tabs/{tab_id}")
    assert response.status_code == 200
    assert db.session.get(Tab, tab_id) is None


def test_add_feed_success(client, mocker):
    user = User.query.first()
    tab = Tab(user_id=user.id, name="General")
    db.session.add(tab)
    db.session.commit()
    tab_id = tab.id

    mock_fetch = mocker.patch("backend.blueprints.feeds.fetch_feed")
    mock_feed = MagicMock()
    mock_feed.feed = {"title": "Test Feed", "link": "http://example.com"}
    mock_feed.entries = []
    mock_fetch.return_value = mock_feed

    response = client.post(
        "/api/feeds", json={"url": "http://example.com/rss", "tab_id": tab_id}
    )
    assert response.status_code == 201
    assert response.json["name"] == "Test Feed"

    assert Subscription.query.count() == 1
    assert Feed.query.filter_by(url="http://example.com/rss").count() == 1


def test_mark_item_read_success(client):
    user = User.query.first()
    tab = Tab(user_id=user.id, name="Test")
    db.session.add(tab)
    feed = Feed(name="Test Feed", url="http://test.com")
    db.session.add(feed)
    db.session.flush()
    sub = Subscription(user_id=user.id, tab_id=tab.id, feed_id=feed.id)
    db.session.add(sub)
    item = FeedItem(feed_id=feed.id, title="Item", link="http://i.com")
    db.session.add(item)
    db.session.commit()
    item_id = item.id

    response = client.post(f"/api/items/{item_id}/read")
    assert response.status_code == 200
    state = UserItemState.query.filter_by(
        user_id=user.id, item_id=item_id).first()
    assert state is not None
    assert state.is_read is True
