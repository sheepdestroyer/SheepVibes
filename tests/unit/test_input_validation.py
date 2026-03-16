import pytest

from backend.app import db
from backend.models import Feed, Tab


def test_tab_name_length_validation_create(client):
    """Test that creating a tab with a name exceeding 100 characters fails."""
    long_name = "a" * 101
    response = client.post("/api/tabs", json={"name": long_name})
    assert response.status_code == 400
    assert "Tab name must not exceed 100 characters" in response.json["error"]


def test_tab_name_length_validation_rename(client):
    """Test that renaming a tab with a name exceeding 100 characters fails."""
    response = client.post("/api/tabs", json={"name": "Test Tab 2"})
    assert response.status_code == 201
    tab_id = response.json["id"]

    long_name = "a" * 101
    response = client.put(f"/api/tabs/{tab_id}", json={"name": long_name})
    assert response.status_code == 400
    assert "Tab name must not exceed 100 characters" in response.json["error"]


def test_feed_url_length_validation_create(client):
    """Test that adding a feed with a URL exceeding 500 characters fails."""
    # We need a tab first
    response = client.post("/api/tabs", json={"name": "Test Tab"})
    assert response.status_code == 201
    tab_id = response.json["id"]

    long_url = "http://example.com/" + "a" * 482  # Total 501 chars
    response = client.post(
        "/api/feeds", json={"url": long_url, "tab_id": tab_id})
    assert response.status_code == 400
    assert "Feed URL must not exceed 500 characters" in response.json["error"]


def test_feed_url_length_validation_update(client):
    """Test that updating a feed with a URL exceeding 500 characters fails."""
    response = client.post("/api/tabs", json={"name": "Test Tab 3"})
    assert response.status_code == 201
    tab_id = response.json["id"]

    response = client.post(
        "/api/feeds", json={"url": "http://example.com/valid", "tab_id": tab_id}
    )
    assert response.status_code == 201
    feed_id = response.json["id"]

    long_url = "http://example.com/" + "a" * 482  # Total 501 chars
    response = client.put(f"/api/feeds/{feed_id}", json={"url": long_url})
    assert response.status_code == 400
    assert "Feed URL must not exceed 500 characters" in response.json["error"]


def test_feed_name_length_validation_update(client):
    """Test that updating a feed with a name exceeding 200 characters fails."""
    response = client.post("/api/tabs", json={"name": "Test Tab 4"})
    assert response.status_code == 201
    tab_id = response.json["id"]

    response = client.post(
        "/api/feeds", json={"url": "http://example.com/valid2", "tab_id": tab_id}
    )
    assert response.status_code == 201
    feed_id = response.json["id"]

    long_name = "a" * 201
    valid_url = "http://example.com/feed.xml"
    response = client.put(
        f"/api/feeds/{feed_id}", json={"url": valid_url, "name": long_name}
    )
    assert response.status_code == 400
    assert "Feed name must not exceed 200 characters" in response.json["error"]
