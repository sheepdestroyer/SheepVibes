import datetime
import pytest
from backend.models import Tab, Feed, FeedItem
from backend.app import db
from backend.tab_service import get_tab_feeds_with_items

def test_get_tab_feeds_with_items_basic(client):
    """
    Test that get_tab_feeds_with_items returns feeds and items correctly.
    """
    # Create Tab
    tab = Tab(name="Test Tab", order=1)
    db.session.add(tab)
    db.session.commit()

    # Create Feed
    feed = Feed(name="Test Feed", url="http://test.com/feed", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Create Items
    # Note: Using naive datetime which models assume to be UTC or handle correctly
    item1 = FeedItem(
        title="Item 1",
        link="http://test.com/item1",
        feed_id=feed.id,
        published_time=datetime.datetime(2024, 1, 1, 12, 0, 0),
        guid="guid1"
    )
    item2 = FeedItem(
        title="Item 2",
        link="http://test.com/item2",
        feed_id=feed.id,
        published_time=datetime.datetime(2024, 1, 2, 12, 0, 0),
        guid="guid2"
    )
    db.session.add(item1)
    db.session.add(item2)
    db.session.commit()

    # Call Service
    result = get_tab_feeds_with_items(tab.id)

    # Verify
    assert len(result) == 1
    feed_data = result[0]
    assert feed_data["id"] == feed.id
    assert len(feed_data["items"]) == 2
    # Check order (newest first)
    assert feed_data["items"][0]["title"] == "Item 2"
    assert feed_data["items"][1]["title"] == "Item 1"

    # Check unread count
    assert feed_data["unread_count"] == 2

def test_get_tab_feeds_with_items_limit(client):
    """
    Test that get_tab_feeds_with_items respects the limit.
    """
    tab = Tab(name="Limit Tab", order=2)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="Limit Feed", url="http://limit.com/feed", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Create 5 items
    for i in range(5):
        item = FeedItem(
            title=f"Item {i}",
            link=f"http://limit.com/item{i}",
            feed_id=feed.id,
            published_time=datetime.datetime(2024, 1, 1, 12, i, 0),
            guid=f"guid{i}"
        )
        db.session.add(item)
    db.session.commit()

    # Limit to 3
    result = get_tab_feeds_with_items(tab.id, limit=3)

    assert len(result) == 1
    assert len(result[0]["items"]) == 3
    assert result[0]["items"][0]["title"] == "Item 4" # Newest (12:04)

def test_get_tab_feeds_empty_tab(client):
    """Test with a tab that has no feeds."""
    tab = Tab(name="Empty Tab", order=3)
    db.session.add(tab)
    db.session.commit()

    result = get_tab_feeds_with_items(tab.id)
    assert result == []

def test_get_tab_feeds_no_items(client):
    """Test with a feed that has no items."""
    tab = Tab(name="No Items Tab", order=4)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="Empty Feed", url="http://empty.com", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    result = get_tab_feeds_with_items(tab.id)
    assert len(result) == 1
    assert result[0]["items"] == []
