import datetime
from datetime import timedelta, timezone

import pytest

from backend.models import Feed, FeedItem, Tab, db


def test_validate_datetime_utc_none():
    """Test that None is handled correctly by the validator."""
    item = FeedItem()
    assert item.validate_datetime_utc("published_time", None) is None


def test_validate_datetime_utc_naive():
    """Test that naive datetime is returned as-is (assumed UTC)."""
    item = FeedItem()
    naive_dt = datetime.datetime(2024, 1, 1, 12, 0, 0)
    validated = item.validate_datetime_utc("published_time", naive_dt)
    assert validated == naive_dt
    assert validated.tzinfo is None


def test_validate_datetime_utc_aware_utc():
    """Test that aware UTC datetime is converted to naive UTC."""
    item = FeedItem()
    utc_dt = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    validated = item.validate_datetime_utc("published_time", utc_dt)
    assert validated == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert validated.tzinfo is None


def test_validate_datetime_utc_aware_non_utc_positive():
    """Test that aware non-UTC datetime (positive offset) is converted to naive UTC."""
    item = FeedItem()
    # +02:00 offset
    other_tz = timezone(timedelta(hours=2))
    other_dt = datetime.datetime(2024, 1, 1, 14, 0, 0, tzinfo=other_tz)
    validated = item.validate_datetime_utc("published_time", other_dt)
    # 14:00 +02:00 is 12:00 UTC
    assert validated == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert validated.tzinfo is None


def test_validate_datetime_utc_aware_non_utc_negative():
    """Test that aware non-UTC datetime (negative offset) is converted to naive UTC."""
    item = FeedItem()
    # -05:00 offset
    other_tz = timezone(timedelta(hours=-5))
    other_dt = datetime.datetime(2024, 1, 1, 7, 0, 0, tzinfo=other_tz)
    validated = item.validate_datetime_utc("published_time", other_dt)
    # 07:00 -05:00 is 12:00 UTC
    assert validated == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert validated.tzinfo is None


def test_feed_item_assignment_validation(client):
    """Test that assignment to model fields triggers the validator."""
    # We need app context for models sometimes, although @validates might work without it
    # But FeedItem might need to be associated with a session for some things.
    # Actually @validates is a pure ORM feature.

    other_tz = timezone(timedelta(hours=2))
    other_dt = datetime.datetime(2024, 1, 1, 14, 0, 0, tzinfo=other_tz)

    item = FeedItem()
    item.published_time = other_dt
    item.fetched_time = other_dt

    assert item.published_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.published_time.tzinfo is None
    assert item.fetched_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.fetched_time.tzinfo is None


def test_feed_item_constructor_validation():
    """Test that passing values to the constructor triggers the validator."""
    other_tz = timezone(timedelta(hours=-5))
    other_dt = datetime.datetime(2024, 1, 1, 7, 0, 0, tzinfo=other_tz)

    item = FeedItem(published_time=other_dt, fetched_time=other_dt)

    assert item.published_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.published_time.tzinfo is None
    assert item.fetched_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.fetched_time.tzinfo is None


def test_feed_item_db_storage(client):
    """Test that values are correctly stored and retrieved from the DB."""
    # Create Tab and Feed
    tab = Tab(name="Validation Tab")
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="Validation Feed",
                url="http://example.com",
                tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    other_tz = timezone(timedelta(hours=2))
    other_dt = datetime.datetime(2024, 1, 1, 14, 0, 0, tzinfo=other_tz)

    item = FeedItem(
        feed_id=feed.id,
        title="Test Item",
        link="http://example.com/item",
        published_time=other_dt,
        fetched_time=other_dt,
    )
    db.session.add(item)
    db.session.commit()

    # Retrieve from DB
    db.session.refresh(item)
    assert item.published_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.published_time.tzinfo is None
    assert item.fetched_time == datetime.datetime(2024, 1, 1, 12, 0, 0)
    assert item.fetched_time.tzinfo is None
