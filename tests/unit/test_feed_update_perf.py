
import datetime
import pytest
import time
from sqlalchemy import event
from backend.app import app
from backend.models import db, Feed, FeedItem, Tab
from backend import feed_service
from unittest.mock import MagicMock

# --- Test Helpers ---

class MockFeedEntry(dict):
    """Mocks a feedparser entry with both dict and attribute access."""
    def __init__(self, **kwargs):
        super().__init__()
        for k, v in kwargs.items():
            self[k] = v
        # Ensure default keys exist if not provided
        if "id" not in self: self["id"] = None
        if "link" not in self: self["link"] = None
        if "title" not in self: self["title"] = None

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None

    def get(self, key, default=None):
        return super().get(key, default)

class MockParsedFeed:
    """Mocks a parsed feed object from feedparser."""
    def __init__(self, entries):
        self.feed = {"title": "Test Feed"}
        self.entries = entries
        self.bozo = 0

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

@pytest.fixture
def captured_queries():
    queries = []
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        # Normalize whitespace for easier checking
        clean_stmt = " ".join(statement.split())
        queries.append(clean_stmt)

    listener = event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    yield queries
    event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

def test_feed_update_query_optimization(db_setup, captured_queries):
    """
    Verifies that processing feed entries uses optimized queries to check for existing items,
    fetching only potential matches (by GUID/Link) rather than the entire feed history.
    """

    # 1. Setup Data
    tab = Tab(name="PerfTab", order=1)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="PerfFeed", url="http://perf.test", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Add 50 existing items
    items = []
    for i in range(50):
        items.append(FeedItem(
            feed_id=feed.id,
            title=f"Item {i}",
            link=f"http://perf.test/{i}",
            guid=f"guid-{i}",
            published_time=datetime.datetime.now(datetime.timezone.utc)
        ))
    db.session.bulk_save_objects(items)
    db.session.commit()

    # 2. Mock new feed data
    # Contains:
    # - 1 New Item (should be added)
    # - 1 Existing Item (should be updated)
    # Total 2 items to check against DB.

    new_entry = MockFeedEntry(
        title="New Item",
        link="http://perf.test/new",
        id="new-guid",
        published_parsed=datetime.datetime.now(datetime.timezone.utc).timetuple()
    )

    existing_entry = MockFeedEntry(
        title="Item 0 Updated",
        link="http://perf.test/0",
        id="guid-0",
        published_parsed=datetime.datetime.now(datetime.timezone.utc).timetuple()
    )

    parsed_feed = MockParsedFeed([new_entry, existing_entry])

    # Clear query log from setup
    captured_queries.clear()

    # 3. Run Function
    feed_service.process_feed_entries(feed, parsed_feed)

    # 4. Analyze Queries
    # Find the SELECT query on feed_items
    select_queries = [
        q for q in captured_queries
        if "SELECT" in q.upper() and "feed_items" in q.lower()
    ]

    print("\n--- Executed SELECT Queries on feed_items ---")
    for q in select_queries:
        print(q)
    print("---------------------------------------------")

    # The unoptimized query looks like:
    # SELECT feed_items.id AS feed_items_id, ... FROM feed_items WHERE feed_items.feed_id = ?

    # The optimized query should include filters for GUID or LINK:
    # ... WHERE feed_items.feed_id = ? AND (feed_items.guid IN (...) OR feed_items.link IN (...))

    has_optimized_query = any(
        "IN (" in q and ("feed_items.guid" in q or "feed_items.link" in q)
        for q in select_queries
    )

    if not has_optimized_query:
        pytest.fail("Optimization MISSING: Did not find a query filtering by GUID/Link IN list.")

def test_feed_update_query_optimization_missing_id(db_setup, captured_queries):
    """
    Verifies optimization works for items without explicit IDs (fallback to hash).
    """

    # 1. Setup Data
    tab = Tab(name="PerfTabNoID", order=2)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="PerfFeedNoID", url="http://perf-noid.test", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    # Add 10 existing items
    items = []
    for i in range(10):
        items.append(FeedItem(
            feed_id=feed.id,
            title=f"Item {i}",
            link=f"http://perf-noid.test/{i}",
            # Use hash logic if we were strict, but simple guid is fine for pre-pop
            guid=f"hash-{i}",
            published_time=datetime.datetime.now(datetime.timezone.utc)
        ))
    db.session.bulk_save_objects(items)
    db.session.commit()

    # 2. Mock new feed data with missing ID
    # This forces fallback to hash generation

    new_entry_no_id = MockFeedEntry(
        title="New Item No ID",
        link="http://perf-noid.test/new",
        # id is missing
        published_parsed=datetime.datetime.now(datetime.timezone.utc).timetuple()
    )

    parsed_feed = MockParsedFeed([new_entry_no_id])

    captured_queries.clear()

    # 3. Run Function
    feed_service.process_feed_entries(feed, parsed_feed)

    # 4. Analyze Queries
    select_queries = [
        q for q in captured_queries
        if "SELECT" in q.upper() and "feed_items" in q.lower()
    ]

    print("\n--- Executed SELECT Queries on feed_items (No ID) ---")
    for q in select_queries:
        print(q)
    print("-----------------------------------------------------")

    has_optimized_query = any(
        "IN (" in q and ("feed_items.guid" in q or "feed_items.link" in q)
        for q in select_queries
    )

    if not has_optimized_query:
        pytest.fail("Optimization MISSING for items without ID: Did not find a query filtering by GUID/Link IN list.")
