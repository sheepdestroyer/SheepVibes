import pytest
from backend.models import Feed, Tab
from backend.extensions import db
from backend.app import app

def test_add_feed_invalid_url_scheme_prevented(client, mocker):
    """Test that feeds cannot be added with malicious URL schemes (Stored XSS prevention)."""
    malicious_url = "javascript:alert('XSS')"

    response = client.post(
        "/api/feeds",
        json={"url": malicious_url}
    )

    assert response.status_code == 400
    assert "error" in response.json

    with app.app_context():
        feed = Feed.query.filter_by(url=malicious_url).first()
        assert feed is None

def test_update_feed_invalid_url_scheme_prevented(client, mocker):
    """Test that existing feeds cannot be updated with malicious URL schemes."""
    # First create a valid feed
    valid_url = "http://example.com/feed.xml"
    with app.app_context():
        tab1 = Tab(name="Tab 1", order=0)
        db.session.add(tab1)
        db.session.commit()

        feed = Feed(url=valid_url, name="Valid Feed", tab_id=tab1.id)
        db.session.add(feed)
        db.session.commit()
        feed_id = feed.id

    malicious_url = "javascript:alert('XSS')"

    response = client.put(
        f"/api/feeds/{feed_id}",
        json={"url": malicious_url}
    )

    assert response.status_code == 400
    assert "error" in response.json

    with app.app_context():
        feed = db.session.get(Feed, feed_id)
        assert feed.url == valid_url
