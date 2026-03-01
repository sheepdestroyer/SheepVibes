import pytest
from backend.models import Feed, Tab, db


def test_add_feed_invalid_scheme_stored_xss(client):
    """
    Test that adding a feed with a malicious scheme (e.g. javascript:)
    is rejected and not stored in the database.
    This prevents Stored XSS in the frontend.
    """
    tab = Tab(name="Security Tab")
    db.session.add(tab)
    db.session.commit()
    tab_id = tab.id

    # Try to add a feed with javascript: scheme
    malicious_url = "javascript:alert('XSS')"
    response = client.post(
        "/api/feeds",
        json={"url": malicious_url, "tab_id": tab_id},
    )

    assert response.status_code == 400
    data = response.get_json()
    assert "Invalid feed URL scheme" in data["error"]

    # Verify that the feed was NOT added to the database
    feed = Feed.query.filter_by(url=malicious_url).first()
    assert feed is None


def test_update_feed_url_invalid_scheme_stored_xss(client):
    """
    Test that updating a feed URL to a malicious scheme (e.g. javascript:)
    is rejected and not updated in the database.
    This prevents Stored XSS in the frontend.
    """
    tab = Tab(name="Security Tab Update")
    db.session.add(tab)
    db.session.commit()

    feed = Feed(tab_id=tab.id, name="Test Feed", url="https://example.com/feed")
    db.session.add(feed)
    db.session.commit()
    feed_id = feed.id

    # Try to update the feed URL to javascript: scheme
    malicious_url = "javascript:alert('XSS_Update')"
    response = client.put(
        f"/api/feeds/{feed_id}",
        json={"url": malicious_url},
    )

    assert response.status_code == 400
    data = response.get_json()
    assert "Invalid feed URL scheme" in data["error"]

    # Verify that the feed URL was NOT updated in the database
    updated_feed = db.session.get(Feed, feed_id)
    assert updated_feed.url == "https://example.com/feed"
    assert updated_feed.url != malicious_url
