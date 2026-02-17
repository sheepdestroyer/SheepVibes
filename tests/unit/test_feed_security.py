from unittest.mock import patch, MagicMock
from backend.models import Feed, Tab, db

def test_add_feed_xss_prevention(client):
    """
    Test that adding a feed with a javascript: URL is rejected.
    """
    # Create a default tab first
    client.post("/api/tabs", json={"name": "Security Tab"})

    # Attempt to add a malicious feed
    malicious_url = "javascript:alert('XSS')"
    response = client.post("/api/feeds", json={
        "url": malicious_url
    })

    # Assert rejection (Should be 400 Bad Request)
    assert response.status_code == 400, f"Should reject javascript: URLs but got {response.status_code}"
    assert "Invalid feed URL" in response.get_json().get("error", "")

    # Verify not in DB
    with client.application.app_context():
        feed = Feed.query.filter_by(url=malicious_url).first()
        assert feed is None, "Malicious feed should not be saved to DB"

def test_update_feed_xss_prevention(client):
    """
    Test that updating a feed to a javascript: URL is rejected.
    """
    # Create a tab
    client.post("/api/tabs", json={"name": "Update Tab"})

    # Create a valid feed first
    with patch("backend.blueprints.feeds.fetch_feed") as mock_fetch:
        mock_parsed = MagicMock()
        mock_parsed.feed = {"title": "Valid Feed", "link": "http://example.com"}
        mock_parsed.entries = []
        mock_fetch.return_value = mock_parsed

        response = client.post("/api/feeds", json={
            "url": "http://example.com/feed.xml"
        })
        assert response.status_code == 201
        feed_id = response.get_json()["id"]

    # Attempt to update to malicious URL
    malicious_url = "javascript:alert('XSS')"

    # If vulnerable, fetch_feed(malicious_url) returns None, but code proceeds to update.
    # So we mock fetch_feed to return None for the malicious URL
    with patch("backend.blueprints.feeds.fetch_feed") as mock_fetch_malicious:
        mock_fetch_malicious.return_value = None

        response = client.put(f"/api/feeds/{feed_id}", json={
            "url": malicious_url
        })

        # Assert rejection (Should be 400 Bad Request)
        assert response.status_code == 400, f"Should reject update to javascript: URL but got {response.status_code}"
        assert "Invalid feed URL" in response.get_json().get("error", "")

        # Verify URL not changed in DB
        with client.application.app_context():
            feed = db.session.get(Feed, feed_id)
            assert feed.url == "http://example.com/feed.xml", "Feed URL should not be updated to malicious URL"
