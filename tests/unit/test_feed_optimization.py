import logging
from unittest.mock import MagicMock

import pytest
from sqlalchemy import event, false
from sqlalchemy.engine import Engine

from backend import feed_service
from backend.app import app
from backend.models import Feed, FeedItem, Tab, db

logger = logging.getLogger(__name__)


@pytest.fixture
def db_setup():
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


class MockFeedEntry(dict):
    def __init__(self, title, link, guid=None, published_parsed=None, **kwargs):
        super().__init__()
        self["title"] = title
        self["link"] = link
        self["id"] = guid
        self["published_parsed"] = published_parsed
        for k, v in kwargs.items():
            self[k] = v

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class MockParsedFeed:
    def __init__(self, title, entries):
        self.feed = {"title": title}
        self.entries = entries


def test_optimization_uses_in_clause(db_setup, caplog):
    """
    Verifies that _collect_new_items uses an IN clause when checking for duplicates,
    instead of fetching all items.
    """
    # Create a tab and feed
    tab = Tab(name="OptTab", order=1)
    db.session.add(tab)
    db.session.commit()
    feed = Feed(name="OptFeed", url="http://opt.feed/rss", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Add some existing items to DB
    for i in range(10):
        item = FeedItem(
            feed_id=feed.id,
            title=f"Item {i}",
            link=f"http://opt.feed/item{i}",
            guid=f"guid{i}",
            published_time=None,
        )
        db.session.add(item)
    db.session.commit()

    # Create parsed feed with some new and some existing items
    entries = []
    # Existing item (should be found)
    entries.append(MockFeedEntry("Item 0", "http://opt.feed/item0", "guid0"))
    # New item
    entries.append(MockFeedEntry(
        "New Item", "http://opt.feed/new", "new_guid"))

    parsed_feed = MockParsedFeed("OptFeed", entries)

    # Capture SQL queries
    queries = []

    @event.listens_for(Engine, "before_cursor_execute")
    def before_cursor_execute(
        conn, cursor, statement, parameters, context, executemany
    ):
        queries.append(statement)

    # Run processing
    with caplog.at_level(logging.INFO):
        feed_service.process_feed_entries(feed, parsed_feed)

    # Analyze queries
    # We look for a query on feed_items that includes "IN" and "feed_id"
    # The query structure should be something like:
    # SELECT ... FROM feed_items WHERE feed_items.feed_id = ? AND (feed_items.guid IN (?, ?) OR feed_items.link IN (?, ?))

    found_optimized_query = False
    for q in queries:
        q_str = str(q).upper()
        if "FROM FEED_ITEMS" in q_str and "IN (" in q_str and "FEED_ID" in q_str:
            found_optimized_query = True
            logger.info(f"Found optimized query: {q_str}")
            break

    assert found_optimized_query, (
        "Did not find a query using IN clause for item deduplication"
    )


def test_fallback_to_fetch_all_on_many_candidates(db_setup):
    """
    Verifies that _collect_new_items falls back to fetching all items
    if there are too many candidates (to avoid SQLite limits).
    """
    # Create feed
    tab = Tab(name="FallbackTab", order=1)
    db.session.add(tab)
    db.session.commit()
    feed = Feed(name="FallbackFeed", url="http://fb.feed/rss", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Simulate many candidates (> 500)
    entries = []
    for i in range(600):
        entries.append(
            MockFeedEntry(f"Item {i}", f"http://fb.feed/item{i}", f"guid{i}")
        )

    parsed_feed = MockParsedFeed("FallbackFeed", entries)

    queries = []

    @event.listens_for(Engine, "before_cursor_execute")
    def before_cursor_execute(
        conn, cursor, statement, parameters, context, executemany
    ):
        queries.append(statement)

    feed_service.process_feed_entries(feed, parsed_feed)

    # We expect a query that does NOT have "IN" clause related to guids/links,
    # but selects from feed_items filtered by feed_id

    fallback_query_found = False
    for q in queries:
        q_str = str(q).upper()
        if "FROM FEED_ITEMS" in q_str and "FEED_ID" in q_str:
            if "IN (" not in q_str:
                fallback_query_found = True
                logger.info(f"Found fallback query: {q_str}")
                break

    assert fallback_query_found, (
        "Should fallback to simple query (no IN clause) for large inputs"
    )


def test_empty_feed_optimization(db_setup):
    """
    Verifies that _collect_new_items handles empty feeds correctly (no errors, specifically NameError).
    """
    # Create feed
    tab = Tab(name="EmptyTab", order=1)
    db.session.add(tab)
    db.session.commit()
    feed = Feed(name="EmptyFeed", url="http://empty.feed/rss", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Empty entries
    parsed_feed = MockParsedFeed("EmptyFeed", [])

    queries = []

    @event.listens_for(Engine, "before_cursor_execute")
    def before_cursor_execute(
        conn, cursor, statement, parameters, context, executemany
    ):
        queries.append(statement)

    # Should not raise exception
    feed_service.process_feed_entries(feed, parsed_feed)

    # Verify query uses "0 = 1" or similar false condition
    # SQLAlchemy `false()` usually renders to `0 = 1` or `False` depending on dialect.

    found_false_query = False
    for q in queries:
        q_str = str(q).upper()
        # In SQLite, false() renders as `0 = 1` usually.
        # Or just checking that it ran without error is mostly enough for the NameError regression.
        # But let's check for optimization.
        if "FROM FEED_ITEMS" in q_str and ("0 = 1" in q_str or "FALSE" in q_str):
            found_false_query = True
            break

    # Actually, SQLAlchemy might not execute the query if it detects it's statically false?
    # No, filter(false()) creates a query with `WHERE 0 = 1`.

    # If no candidates, we expect the query to be executed with false condition.
    assert found_false_query, (
        "Should execute query with false condition for empty candidates"
    )
