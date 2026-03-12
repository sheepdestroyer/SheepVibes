import pytest
from backend.app import db
from backend.models import Tab, Feed, FeedItem
from backend.feed_service import _collect_new_items
from sqlalchemy import event
from contextlib import contextmanager

class MockFeedEntry:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"'MockFeedEntry' object has no attribute '{name}'")

class MockParsedFeed:
    def __init__(self, entries):
        self.entries = [MockFeedEntry(e) for e in entries]

@contextmanager
def count_queries():
    """Context manager to count SQL queries executed within the block."""
    query_count = [0]

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield query_count
    finally:
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

def test_collect_new_items_optimization(client):
    """
    Verify that _collect_new_items optimizes existing items query:
    1. Returns 0 queries (or minimal false query) for empty candidates.
    2. Uses IN query for a small number of candidates.
    3. Falls back to full fetch for a large number of candidates.
    """
    tab = Tab(name="Optimization Tab", order=100)
    feed = Feed(name="Optimization Feed", url="http://example.com/opt_feed", tab=tab)
    db.session.add(tab)
    db.session.add(feed)
    db.session.commit()

    db.session.refresh(feed)

    # Add 100 existing items to the database to ensure the feed has some content
    for i in range(100):
        item = FeedItem(
            feed=feed,
            title=f"Existing {i}",
            link=f"http://example.com/opt_feed/{i}",
            guid=f"guid-ext-{i}"
        )
        db.session.add(item)
    db.session.commit()
    db.session.refresh(feed)

    # 1. Test empty feed (0 candidates)
    empty_parsed = MockParsedFeed([])
    with count_queries() as qc_empty:
        new_items = _collect_new_items(feed, empty_parsed)

    assert len(new_items) == 0
    assert qc_empty[0] <= 1 # Can be 1 false query, but shouldn't be full table scan/load.

    # 2. Test small update (e.g. 5 candidates)
    small_entries = [
        {"title": f"New {i}", "link": f"http://example.com/opt_feed/new_{i}", "id": f"guid-new-{i}"}
        for i in range(5)
    ]
    small_parsed = MockParsedFeed(small_entries)
    with count_queries() as qc_small:
        new_items = _collect_new_items(feed, small_parsed)

    assert len(new_items) == 5
    # Should use IN clause, which is 1 query.
    assert qc_small[0] == 1

    # 3. Test large update (>= 500 candidates)
    # We only need 500 candidate guids/links total.
    # 250 entries will produce 250 guids + 250 links = 500 candidates.
    large_entries = [
        {"title": f"Large {i}", "link": f"http://example.com/opt_feed/large_{i}", "id": f"guid-large-{i}"}
        for i in range(250)
    ]
    large_parsed = MockParsedFeed(large_entries)
    with count_queries() as qc_large:
        new_items = _collect_new_items(feed, large_parsed)

    assert len(new_items) == 250
    # Should fallback to a single fetch-all query
    assert qc_large[0] == 1
