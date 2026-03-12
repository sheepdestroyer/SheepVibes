import pytest
from backend.models import Feed, Tab
from backend.app import db, app

def test_add_feed_xss_prevention(client):
    """Test that attempting to add a feed with a malicious scheme is rejected."""
    # Setup: Create a tab
    response = client.post("/api/tabs", json={"name": "Test Tab"})
    assert response.status_code == 201

    # Attempt to add a feed with a javascript: URI
    malicious_url = "javascript:alert('XSS')"
    response = client.post("/api/feeds", json={"url": malicious_url})

    # Assert it is rejected
    assert response.status_code == 400
    assert "Invalid feed URL scheme" in response.get_json()["error"]

    # Verify it was not stored in the database
    with app.app_context():
        feed = Feed.query.filter_by(url=malicious_url).first()
        assert feed is None

def test_update_feed_xss_prevention(client):
    """Test that attempting to update a feed URL to a malicious scheme is rejected."""
    # Setup: Create a tab and a valid feed
    client.post("/api/tabs", json={"name": "Test Tab"})

    valid_url = "http://example.com/feed.xml"
    response = client.post("/api/feeds", json={"url": valid_url})
    assert response.status_code == 201

    feed_id = response.get_json()["id"]

    # Attempt to update the feed with a javascript: URI
    malicious_url = "javascript:alert('XSS')"
    response = client.put(f"/api/feeds/{feed_id}", json={"url": malicious_url})

    # Assert it is rejected
    assert response.status_code == 400
    assert "Invalid feed URL scheme" in response.get_json()["error"]

    # Verify it was not updated in the database
    with app.app_context():
        feed = db.session.get(Feed, feed_id)
        assert feed.url == valid_url
