import pytest

from backend.app import app
from backend.models import Feed, Tab, db


@pytest.fixture
def setup_tabs_and_feeds(client):
    with app.app_context():
        tab1 = Tab(name="Tab 1", order=1)
        db.session.add(tab1)
        db.session.commit()
        tab1_id = tab1.id

        feed1 = Feed(name="Test Feed",
                     url="http://test.com/feed.xml",
                     tab_id=tab1_id)
        db.session.add(feed1)
        db.session.commit()
        feed1_id = feed1.id

        return {"tab1_id": tab1_id, "feed1_id": feed1_id}


def test_add_feed_xss_prevention(client, setup_tabs_and_feeds):
    tab_id = setup_tabs_and_feeds["tab1_id"]

    # Payload
    malicious_url = "javascript:alert('XSS')"

    response = client.post("/api/feeds",
                           json={
                               "url": malicious_url,
                               "tab_id": tab_id
                           })

    assert response.status_code == 400

    # Check it wasn't added
    with app.app_context():
        feed = db.session.query(Feed).filter_by(url=malicious_url).first()
        assert feed is None


def test_update_feed_xss_prevention(client, setup_tabs_and_feeds):
    feed_id = setup_tabs_and_feeds["feed1_id"]

    malicious_url = "javascript:alert('XSS')"

    response = client.put(f"/api/feeds/{feed_id}", json={"url": malicious_url})

    assert response.status_code == 400

    # Check it wasn't updated
    with app.app_context():
        feed = db.session.get(Feed, feed_id)
        assert feed.url != malicious_url
