import pytest

from backend.models import Feed, FeedItem, Tab, db


def test_get_tabs_unread_counts(client):
    """Test GET /api/tabs returns correct unread counts with optimized query."""

    # Create tabs
    tab1 = Tab(name="Tab 1", order=0)
    tab2 = Tab(name="Tab 2", order=1)
    db.session.add_all([tab1, tab2])
    db.session.commit()

    # Create feeds
    feed1 = Feed(tab_id=tab1.id, name="Feed 1", url="url1")
    feed2 = Feed(tab_id=tab1.id, name="Feed 2", url="url2")
    feed3 = Feed(tab_id=tab2.id, name="Feed 3", url="url3")
    db.session.add_all([feed1, feed2, feed3])
    db.session.commit()

    # Create items
    # Tab 1: Feed 1 has 2 unread, Feed 2 has 1 unread -> Total 3
    items = [
        FeedItem(feed_id=feed1.id, title="Item 1", link="l1", is_read=False),
        FeedItem(feed_id=feed1.id, title="Item 2", link="l2", is_read=False),
        FeedItem(feed_id=feed1.id, title="Item 3", link="l3", is_read=True),
        FeedItem(feed_id=feed2.id, title="Item 4", link="l4", is_read=False),
        # Tab 2: Feed 3 has 0 unread
        FeedItem(feed_id=feed3.id, title="Item 5", link="l5", is_read=True),
    ]
    db.session.add_all(items)
    db.session.commit()

    # Act
    response = client.get("/api/tabs")

    # Assert
    assert response.status_code == 200
    data = response.json
    data.sort(key=lambda x: x["order"])

    assert data[0]["name"] == "Tab 1"
    assert data[0]["unread_count"] == 3

    assert data[1]["name"] == "Tab 2"
    assert data[1]["unread_count"] == 0
