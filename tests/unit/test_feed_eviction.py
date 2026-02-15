import datetime
from datetime import timezone

import pytest

from backend.app import app
from backend.constants import EVICTION_LIMIT_PER_RUN, MAX_ITEMS_PER_FEED
from backend.feed_service import _enforce_feed_limit
from backend.models import Feed, FeedItem, Tab, db


def create_dummy_items(feed_id, count, start_date=None):
    """Helper to create dummy feed items."""
    items = []
    base_date = start_date or datetime.datetime.now(timezone.utc)
    for i in range(count):
        # Create items with decreasing dates (newest first in loop, but we assign dates)
        # We want to simulate a feed. Let's make items with dates from base_date - i days.
        pub_date = base_date - datetime.timedelta(days=i)
        item = FeedItem(
            feed_id=feed_id,
            title=f"Item {i}",
            link=f"http://example.com/item/{i}",
            guid=f"guid-{i}",
            published_time=pub_date,
            fetched_time=base_date,  # fetched now
        )
        items.append(item)
    db.session.add_all(items)
    db.session.commit()
    return items


def create_feed_with_tab():
    """Helper to create a feed and its required tab."""
    tab = Tab(name="Test Tab", order=1)
    db.session.add(tab)
    db.session.flush()  # get ID

    feed = Feed(name="Test Feed", url="http://example.com/feed", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()
    return feed


def test_eviction_under_limit(client):
    """Test that no items are evicted if under the limit."""
    with app.app_context():
        feed = create_feed_with_tab()

        create_dummy_items(feed.id, MAX_ITEMS_PER_FEED - 1)

        _enforce_feed_limit(feed)

        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED - 1


def test_eviction_over_limit_within_cap(client):
    """Test eviction when over limit but within single run cap."""
    with app.app_context():
        feed = create_feed_with_tab()

        # Create 10 items over the limit
        total_items = MAX_ITEMS_PER_FEED + 10
        create_dummy_items(feed.id, total_items)

        _enforce_feed_limit(feed)

        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED

        # Verify oldest were deleted (items with larger 'i' in helper have older dates)
        # helper creates items 0 to total-1. Item 0 is newest. Item total-1 is oldest.
        # We expect items 0 to MAX-1 to be kept.
        # Items MAX to total-1 should be deleted.

        # Check if item 0 (newest) exists
        newest = FeedItem.query.filter_by(guid="guid-0").first()
        assert newest is not None

        # Check if item total-1 (oldest) is gone
        oldest_guid = f"guid-{total_items - 1}"
        oldest = FeedItem.query.filter_by(guid=oldest_guid).first()
        assert oldest is None


def test_eviction_over_limit_exceeding_cap(client):
    """Test that eviction is capped by EVICTION_LIMIT_PER_RUN."""
    with app.app_context():
        feed = create_feed_with_tab()

        # Create many items over the limit
        excess_items = EVICTION_LIMIT_PER_RUN + 50
        total_items = MAX_ITEMS_PER_FEED + excess_items
        create_dummy_items(feed.id, total_items)

        _enforce_feed_limit(feed)

        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        # Should have removed EVICTION_LIMIT_PER_RUN items
        expected_remaining = total_items - EVICTION_LIMIT_PER_RUN
        assert count == expected_remaining
        assert count > MAX_ITEMS_PER_FEED  # Still over limit

        # Run again to clear the rest
        _enforce_feed_limit(feed)
        count_after_2nd = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count_after_2nd == MAX_ITEMS_PER_FEED


def test_eviction_null_handling(client):
    """Test that items with NULL dates are treated as oldest and evicted."""
    with app.app_context():
        feed = create_feed_with_tab()

        # Create MAX items with dates
        create_dummy_items(feed.id, MAX_ITEMS_PER_FEED)

        # Add an item with NULL date
        null_item = FeedItem(
            feed_id=feed.id,
            title="Null Item",
            link="http://example.com/null",
            guid="guid-null",
            published_time=None,
            fetched_time=None,
        )
        db.session.add(null_item)
        db.session.commit()

        # Now we have MAX + 1 items. Null item should be considered "oldest" (nulls last in descending order)
        # Wait, DESC NULLS LAST means: [Date, Date, ..., NULL].
        # We OFFSET MAX (skipping the Dates).
        # We select the NULL item.
        # So NULL item should be evicted.

        _enforce_feed_limit(feed)

        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED

        # Verify null item is gone
        check_null = FeedItem.query.filter_by(guid="guid-null").first()
        assert check_null is None

        # Verify a dated item (newest) is still there
        check_dated = FeedItem.query.filter_by(guid="guid-0").first()
        assert check_dated is not None
