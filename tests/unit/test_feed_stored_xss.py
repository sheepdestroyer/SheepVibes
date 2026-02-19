import pytest

from backend.models import Feed, Tab, db


def test_add_feed_xss_prevention(client):
    """
    Test that adding a feed with a javascript: URL is rejected to prevent Stored XSS.
    """
    # Create a default tab first
    tab = Tab(name="Test Tab")
    db.session.add(tab)
    db.session.commit()

    xss_url = "javascript:alert(1)"
    response = client.post("/api/feeds", json={"url": xss_url})

    # Assert that the application rejects the malicious URL
    assert response.status_code == 400, (
        "Expected 400 Bad Request for invalid URL scheme"
    )
    assert "Invalid feed URL" in response.get_json()["error"]

    # Verify the feed was NOT stored in the database
    feed = Feed.query.filter_by(url=xss_url).first()
    assert feed is None, "Feed with malicious URL should not be stored"


def test_update_feed_url_xss_prevention(client):
    """
    Test that updating a feed with a javascript: URL is rejected.
    """
    # Create a default tab and a valid feed first
    tab = Tab(name="Test Tab")
    db.session.add(tab)
    db.session.commit()

    valid_feed = Feed(tab_id=tab.id, name="Valid Feed",
                      url="http://example.com/feed")
    db.session.add(valid_feed)
    db.session.commit()

    xss_url = "javascript:alert(1)"
    response = client.put(f"/api/feeds/{valid_feed.id}", json={"url": xss_url})

    # Assert rejection
    assert response.status_code == 400
    assert "Invalid feed URL" in response.get_json()["error"]

    # Verify URL was NOT updated
    db.session.refresh(valid_feed)
    assert valid_feed.url == "http://example.com/feed"
