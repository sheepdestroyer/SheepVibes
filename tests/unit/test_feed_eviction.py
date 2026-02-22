import datetime
from datetime import timezone
from backend.app import app
from backend.constants import EVICTION_LIMIT_PER_RUN, MAX_ITEMS_PER_FEED
from backend.feed_service import _enforce_feed_limit
from backend.models import Feed, FeedItem, Tab, db, User

def create_dummy_items(feed_id, count, start_date=None):
    items = []
    base_date = start_date or datetime.datetime.now(timezone.utc)
    for i in range(count):
        pub_date = base_date - datetime.timedelta(days=i)
        item = FeedItem(feed_id=feed_id, title=f"Item {i}", link=f"http://example.com/item/{i}", guid=f"guid-{i}", published_time=pub_date, fetched_time=base_date)
        items.append(item)
    db.session.add_all(items)
    db.session.commit()
    return items

def create_feed():
    user = User.query.first()
    tab = Tab(user_id=user.id, name="Test Tab", order=1)
    db.session.add(tab)
    db.session.flush()
    feed = Feed(name="Test Feed", url="http://example.com/feed")
    db.session.add(feed)
    db.session.commit()
    return feed

def test_eviction_under_limit(client):
    with app.app_context():
        feed = create_feed()
        create_dummy_items(feed.id, MAX_ITEMS_PER_FEED - 1)
        _enforce_feed_limit(feed)
        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED - 1

def test_eviction_at_limit(client):
    with app.app_context():
        feed = create_feed()
        create_dummy_items(feed.id, MAX_ITEMS_PER_FEED)
        _enforce_feed_limit(feed)
        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED

def test_eviction_over_limit_within_cap(client):
    with app.app_context():
        feed = create_feed()
        total_items = MAX_ITEMS_PER_FEED + 10
        create_dummy_items(feed.id, total_items)
        _enforce_feed_limit(feed)
        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        assert count == MAX_ITEMS_PER_FEED
        newest = FeedItem.query.filter_by(guid="guid-0").first()
        assert newest is not None
        oldest_guid = f"guid-{total_items - 1}"
        oldest = FeedItem.query.filter_by(guid=oldest_guid).first()
        assert oldest is None

def test_eviction_over_limit_exceeding_cap(client):
    with app.app_context():
        feed = create_feed()
        excess_items = EVICTION_LIMIT_PER_RUN + 50
        total_items = MAX_ITEMS_PER_FEED + excess_items
        create_dummy_items(feed.id, total_items)
        _enforce_feed_limit(feed)
        count = FeedItem.query.filter_by(feed_id=feed.id).count()
        expected_remaining = total_items - EVICTION_LIMIT_PER_RUN
        assert count == expected_remaining
        _enforce_feed_limit(feed)
        assert FeedItem.query.filter_by(feed_id=feed.id).count() == MAX_ITEMS_PER_FEED

def test_eviction_null_handling(client):
    with app.app_context():
        feed = create_feed()
        create_dummy_items(feed.id, MAX_ITEMS_PER_FEED)
        null_item = FeedItem(feed_id=feed.id, title="Null Item", link="http://example.com/null", guid="guid-null", published_time=None, fetched_time=None)
        db.session.add(null_item)
        db.session.commit()
        _enforce_feed_limit(feed)
        assert FeedItem.query.filter_by(feed_id=feed.id).count() == MAX_ITEMS_PER_FEED
        assert FeedItem.query.filter_by(guid="guid-null").first() is None
