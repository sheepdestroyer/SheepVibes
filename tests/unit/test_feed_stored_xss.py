import pytest

from backend.app import app
from backend.models import Feed, Tab, db


def test_add_feed_stored_xss(client):
    """Test that adding a feed with a javascript: URL is blocked."""
    with app.app_context():
        tab = Tab(name="XSS Tab", order=0)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    response = client.post("/api/feeds",
                           json={
                               "url": "javascript:alert(1)",
                               "tab_id": tab_id
                           })
    assert response.status_code == 400
    assert "Invalid" in response.get_json()["error"]


def test_update_feed_url_stored_xss(client):
    """Test that updating a feed to a javascript: URL is blocked."""
    with app.app_context():
        tab = Tab(name="XSS Tab 2", order=1)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id
        feed = Feed(tab_id=tab_id,
                    name="Valid Feed",
                    url="https://example.com/feed.xml")
        db.session.add(feed)
        db.session.commit()
        feed_id = feed.id

    response = client.put(f"/api/feeds/{feed_id}",
                          json={
                              "url": "javascript:alert(2)",
                              "name": "New Name"
                          })
    assert response.status_code == 400
    assert "Invalid" in response.get_json()["error"]
