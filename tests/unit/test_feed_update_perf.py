import datetime
import logging

import pytest
from sqlalchemy import event

from backend import feed_service
from backend.app import app
from backend.models import Feed, FeedItem, Tab, db

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("perf_test")


class MockFeedEntry(dict):
    """Mocks a feedparser entry."""

    def __init__(self, title, link, guid=None, **kwargs):
        super().__init__()
        self["title"] = title
        self["link"] = link
        self["id"] = guid
        self["published_parsed"] = kwargs.get("published_parsed")
        self["published"] = kwargs.get("published")

    @property
    def guid(self):
        return self.get("id")


class MockParsedFeed:

    def __init__(self, entries):
        self.feed = {"title": "Test Feed"}
        self.entries = entries


@pytest.fixture
def db_session():
    """Sets up a clean database session for the test."""
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()


def test_feed_update_query_optimization(db_session):
    """
    Benchmarks the query used during a feed update.
    Ensures that the query is optimized to fetch only relevant items (using GUID/Link filters)
    instead of fetching all items for the feed.
    """
    # 1. Setup Data
    tab = Tab(name="PerfTab", order=1)
    db_session.add(tab)
    db_session.commit()

    feed = Feed(name="PerfFeed", url="http://perf.com/rss", tab_id=tab.id)
    db_session.add(feed)
    db_session.commit()

    # Create 100 existing items
    items = []
    base_time = datetime.datetime.now(datetime.timezone.utc)
    for i in range(100):
        items.append(
            FeedItem(
                feed_id=feed.id,
                title=f"Item {i}",
                link=f"http://perf.com/item{i}",
                guid=f"guid-{i}",
                published_time=base_time - datetime.timedelta(minutes=i),
            ))
    db_session.add_all(items)
    db_session.commit()

    # 2. Simulate Update Payload
    entries = []
    # Existing items 0-4 (5 items)
    for i in range(5):
        entries.append(
            MockFeedEntry(
                title=f"Item {i}",
                link=f"http://perf.com/item{i}",
                guid=f"guid-{i}",
                published=(base_time -
                           datetime.timedelta(minutes=i)).isoformat(),
            ))
    # New item
    entries.append(
        MockFeedEntry(
            title="New Item",
            link="http://perf.com/new",
            guid="guid-new",
            published=base_time.isoformat(),
        ))

    # New item without GUID (tests synthetic GUID path)
    entries.append(
        MockFeedEntry(
            title="No GUID Item",
            link="http://perf.com/noguid",
            guid=None,  # feedparser 'id' is None
            published=base_time.isoformat(),
        ))

    parsed_feed = MockParsedFeed(entries)

    # 3. Capture SQL
    queries = []

    def before_cursor_execute(conn, cursor, statement, parameters, context,
                              executemany):
        # Filter for the relevant query on feed_items
        if "SELECT feed_items.id" in statement and "FROM feed_items" in statement:
            queries.append(statement)

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)

    # 4. Run Update
    logger.info("Starting process_feed_entries...")
    feed_service.process_feed_entries(feed, parsed_feed)

    event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

    logger.info(f"Captured {len(queries)} relevant queries.")

    found_optimized_query = False
    for q in queries:
        logger.info(f"Query: {q}")

        # Check if query has IN clause for GUIDs or Links
        if "feed_items.guid IN" in q or "feed_items.link IN" in q:
            logger.info("OPTIMIZED QUERY DETECTED: Contains GUID/Link filter.")
            found_optimized_query = True
            break
        else:
            logger.info("Query does not contain optimization filters.")

    assert found_optimized_query, (
        "Did not detect optimized query with GUID/Link filters. It seems to be fetching all items."
    )
