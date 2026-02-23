import datetime
import os
import unittest
from datetime import timezone
from unittest.mock import MagicMock, patch

from backend.app import app, cache
from backend.extensions import db
from backend.feed_service import _collect_new_items, parse_published_time
from backend.models import Feed, FeedItem


class TestFeedOptimization(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app.config["CACHE_TYPE"] = "SimpleCache"

        # Reset extensions
        if "sqlalchemy" in self.app.extensions:
            del self.app.extensions["sqlalchemy"]
        if "cache" in self.app.extensions:
            del self.app.extensions["cache"]

        db.init_app(self.app)
        cache.init_app(self.app)

        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        cache.clear()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_collect_new_items_optimization(self):
        """Test that _collect_new_items correctly identifies new items and updates existing ones."""
        # Setup
        feed = Feed(tab_id=1, name="Test Feed", url="http://example.com/feed")
        db.session.add(feed)
        db.session.commit()

        # Create 100 existing items
        for i in range(100):
            item = FeedItem(
                feed_id=feed.id,
                title=f"Item {i}",
                link=f"http://example.com/item/{i}",
                guid=f"guid-{i}",
                published_time=datetime.datetime.now(timezone.utc),
            )
            db.session.add(item)
        db.session.commit()

        # Mock parsed feed with:
        # - 5 existing items (should be updated if changed, or ignored)
        # - 5 new items (should be added)
        entries = []

        # Existing items (indices 95-99)
        # We need update these items, so we change title
        for i in range(95, 100):
            entry = MagicMock()
            entry.get.side_effect = lambda k, d=None, i=i: {
                "title": f"Item {i} Updated",
                "link": f"http://example.com/item/{i}",
                "id": f"guid-{i}",
            }.get(k, d)
            entry.published_parsed = None
            entry.published = None
            entries.append(entry)

        # New items (indices 100-104)
        for i in range(100, 105):
            entry = MagicMock()
            entry.get.side_effect = lambda k, d=None, i=i: {
                "title": f"Item {i}",
                "link": f"http://example.com/item/{i}",
                "id": f"guid-{i}",
            }.get(k, d)
            entry.published_parsed = None
            entry.published = None
            entries.append(entry)

        parsed_feed = MagicMock()
        parsed_feed.entries = entries

        # We patch parse_published_time where it is defined/imported in feed_service
        # Note: feed_service imports parse_published_time from itself (defined in same file)
        # but _collect_new_items calls it directly.
        # So we patch 'backend.feed_service.parse_published_time'

        with patch("backend.feed_service.parse_published_time") as mock_parse_time:
            mock_parse_time.return_value = datetime.datetime.now(timezone.utc)

            # Run
            items_to_add = _collect_new_items(feed, parsed_feed)

            # Assert
            # 5 new items should be returned to add
            self.assertEqual(len(items_to_add), 5)

            # Check new items
            new_guids = {item.guid for item in items_to_add}
            expected_new_guids = {f"guid-{i}" for i in range(100, 105)}
            self.assertEqual(new_guids, expected_new_guids)

            # Check updates
            # Items 95-99 should have updated titles
            # Since _collect_new_items updates items in DB directly (synchronize_session=False)
            # We need to query them fresh
            updated_items = FeedItem.query.filter(
                FeedItem.feed_id == feed.id,
                FeedItem.guid.in_([f"guid-{i}" for i in range(95, 100)]),
            ).all()
            for item in updated_items:
                self.assertTrue(
                    item.title.endswith("Updated"),
                    f"Item {item.guid} title not updated: {item.title}",
                )

    def test_collect_new_items_fallback(self):
        """Test fallback to full fetch if too many entries."""
        # Setup
        feed = Feed(tab_id=1, name="Large Feed",
                    url="http://example.com/large")
        db.session.add(feed)
        db.session.commit()

        # Mock parsed feed with 600 entries ( > 500 limit)
        entries = []
        for i in range(600):
            entry = MagicMock()
            entry.get.side_effect = lambda k, d=None, i=i: {
                "title": f"Item {i}",
                "link": f"http://example.com/item/{i}",
                "id": f"guid-{i}",
            }.get(k, d)
            entry.published_parsed = None
            entry.published = None
            entries.append(entry)

        parsed_feed = MagicMock()
        parsed_feed.entries = entries

        with patch("backend.feed_service.parse_published_time") as mock_parse_time:
            mock_parse_time.return_value = datetime.datetime.now(timezone.utc)

            items_to_add = _collect_new_items(feed, parsed_feed)

            # All 600 should be new
            self.assertEqual(len(items_to_add), 600)


if __name__ == "__main__":
    unittest.main()
