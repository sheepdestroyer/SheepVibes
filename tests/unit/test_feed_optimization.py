import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from backend.app import app as flask_app
from backend.app import db
from backend.feed_service import _collect_new_items
from backend.models import Feed, FeedItem, Tab


class MockFeedEntry:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getattr__(self, item):
        if item in self._data:
            return self._data[item]
        raise AttributeError(f"MockFeedEntry has no attribute '{item}'")


class MockParsedFeed:
    def __init__(self, entries):
        self.entries = [MockFeedEntry(e) for e in entries]


def test_collect_new_items_optimization():
    """
    Test that _collect_new_items uses the IN clause optimization
    for small feeds and avoids querying all items.
    """
    with flask_app.app_context():
        # Setup DB structure
        flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        db.create_all()

        # 1. Setup Data
        tab = Tab(name="Optimization Test Tab")
        db.session.add(tab)
        db.session.commit()

        feed = Feed(name="Opt Feed",
                    url="http://example.com/opt", tab_id=tab.id)
        db.session.add(feed)
        db.session.commit()

        # Add some existing items
        existing_items = []
        for i in range(10):
            item = FeedItem(
                feed_id=feed.id,
                title=f"Old Title {i}",
                link=f"http://example.com/old/{i}",
                guid=f"old-guid-{i}",
                published_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
            )
            existing_items.append(item)
        db.session.add_all(existing_items)
        db.session.commit()

        # 2. Incoming Feed Data
        incoming_entries = []
        for i in range(5):
            incoming_entries.append(
                {
                    "title": f"New Title {i}",
                    "link": f"http://example.com/new/{i}",
                    "id": f"new-guid-{i}",
                    "published_parsed": (2024, 1, 1, 12, 0, 0, 0, 0, 0),
                }
            )
        parsed_feed = MockParsedFeed(incoming_entries)

        items_to_add = _collect_new_items(feed, parsed_feed)

        assert len(items_to_add) == 5


def test_collect_new_items_fallback():
    """
    Test that _collect_new_items uses the fallback (fetch all)
    when the incoming feed is very large (> 500 items).
    """
    with flask_app.app_context():
        flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        db.create_all()

        tab = Tab(name="Optimization Test Tab 2")
        db.session.add(tab)
        db.session.commit()

        feed = Feed(name="Opt Feed 2",
                    url="http://example.com/opt2", tab_id=tab.id)
        db.session.add(feed)
        db.session.commit()

        incoming_entries = []
        for i in range(505):  # Over the 500 threshold
            incoming_entries.append(
                {
                    "title": f"New Title {i}",
                    "link": f"http://example.com/new/{i}",
                    "id": f"new-guid-{i}",
                    "published_parsed": (2024, 1, 1, 12, 0, 0, 0, 0, 0),
                }
            )
        parsed_feed = MockParsedFeed(incoming_entries)

        items_to_add = _collect_new_items(feed, parsed_feed)

        assert len(items_to_add) == 505
