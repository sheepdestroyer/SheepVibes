import pytest

from backend.app import app, db
from backend.models import Feed, Tab


def test_add_feed_malicious_url(client):
    tab = Tab(name="Default Tab")
    db.session.add(tab)
    db.session.commit()
    response = client.post(
        "/api/feeds", json={"url": "javascript:alert(1)", "tab_id": tab.id}
    )
    assert response.status_code == 400
    assert b"Invalid feed URL" in response.data


def test_update_feed_malicious_url(client):
    tab = Tab(name="Default Tab")
    db.session.add(tab)
    db.session.commit()
    feed = Feed(name="Valid Feed",
                url="http://example.com/feed.xml", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    response = client.put(
        f"/api/feeds/{feed.id}", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert b"Invalid feed URL" in response.data
