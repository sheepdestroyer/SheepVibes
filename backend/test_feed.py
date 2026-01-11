#!/usr/bin/env python3
"""
Test script for the feed service functionality.
This script can be used to test feed fetching and processing without running the full application.
"""
import pytest
import sys
import logging
import datetime # <--- Added import for datetime
from sqlalchemy.exc import IntegrityError # <--- Added import for IntegrityError
from .app import app # Import app for context
from .models import db, Feed, Tab, FeedItem # <--- Added FeedItem import
from . import feed_service # Import feed_service relatively

# Set up logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sheepvibes_test')

@pytest.fixture
def db_setup():
    """Pytest fixture to set up the Flask app for testing with an in-memory DB."""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    with app.app_context():
        db.create_all()
        yield app # Provide the app instance, can also yield db if needed
        db.session.remove()
        db.drop_all()

@pytest.mark.skip(reason="This test is designed for manual execution with a URL parameter, not for automated pytest runs.")
def test_fetch_feed(url):
    """Test fetching a feed from a given URL"""
    logger.info(f"Testing feed fetch from: {url}")
    parsed_feed = feed_service.fetch_feed(url)
    
    if not parsed_feed:
        logger.error("Failed to fetch feed")
        return False # Or raise an assertion error for pytest
    
    logger.info(f"Successfully fetched feed: {parsed_feed.feed.get('title', 'Unknown')}")
    logger.info(f"Found {len(parsed_feed.entries)} entries")
    
    # Print first few entries
    for i, entry in enumerate(parsed_feed.entries[:3]):
        logger.info(f"Entry {i+1}: {entry.title}")
    
    assert parsed_feed is not None # Example assertion for pytest
    return True

def add_test_feed(url, tab_name="Home"):
    """Add a test feed to the database (helper function, not a test itself)."""
    # This function assumes an app context is active if called from a test using db_setup
    # Find or create tab
    tab = Tab.query.filter_by(name=tab_name).first()
    if not tab:
        logger.info(f"Creating new tab: {tab_name}")
        tab = Tab(name=tab_name, order=0)
        db.session.add(tab)
        db.session.commit()

    # Fetch feed to get title
    parsed_feed = feed_service.fetch_feed(url)
    if not parsed_feed:
        logger.error(f"Failed to fetch feed from {url}")
        return None
        
    feed_title = parsed_feed.feed.get('title', 'Unknown Feed')

    # Check if feed already exists
    existing_feed = Feed.query.filter_by(url=url).first()
    if existing_feed:
        logger.info(f"Feed already exists: {feed_title}")
        return existing_feed
        
    # Create new feed
    logger.info(f"Adding new feed: {feed_title}")
    feed = Feed(
        tab_id=tab.id,
        name=feed_title,
        url=url
    )
    db.session.add(feed)
    db.session.commit()

    # Process feed entries
    new_items = feed_service.process_feed_entries(feed, parsed_feed)
    logger.info(f"Added {new_items} new items for feed '{feed.name}'")

    return feed

# --- Mocks and Test Data ---

class MockFeedEntry:
    def __init__(self, title, link, guid=None, published_parsed=None, published=None, updated=None, created=None, **kwargs):
        self.title = title
        self.link = link
        self.id = guid # feedparser uses 'id' for guid
        self.published_parsed = published_parsed # feedparser struct_time
        self.published = published
        self.updated = updated
        self.created = created
        # Allow other attributes like 'dc_date'
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

class MockParsedFeed:
    def __init__(self, feed_title, entries):
        self.feed = {'title': feed_title}
        self.entries = entries
        self.bozo = 0 # 0 means not ill-formed

# --- New Pytest Tests ---

def test_parse_published_time(db_setup): # db_setup for app context if any part of dateutil needs it (unlikely but safe)
    """Test the parse_published_time function with various inputs."""
    logger.info("Testing parse_published_time function")

    # Scenario 1: Valid published_parsed (struct_time)
    # struct_time for 2024-01-15 10:30:00 UTC
    entry1_time_struct = (2024, 1, 15, 10, 30, 0, 0, 15, 0) # tm_isdst=0 (UTC)
    entry1 = MockFeedEntry(title="Entry 1", link="http://example.com/1", published_parsed=entry1_time_struct)
    dt1 = feed_service.parse_published_time(entry1)
    assert dt1 is not None
    assert dt1.year == 2024 and dt1.month == 1 and dt1.day == 15
    assert dt1.hour == 10 and dt1.minute == 30
    assert dt1.tzinfo == datetime.timezone.utc

    # Scenario 2: Valid 'published' string
    entry2 = MockFeedEntry(title="Entry 2", link="http://example.com/2", published="2024-02-20T12:00:00Z")
    dt2 = feed_service.parse_published_time(entry2)
    assert dt2 is not None
    assert dt2 == datetime.datetime(2024, 2, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)

    # Scenario 3: Valid 'updated' string
    entry3 = MockFeedEntry(title="Entry 3", link="http://example.com/3", updated="Sun, 10 Mar 2024 15:45:30 +0200")
    dt3 = feed_service.parse_published_time(entry3)
    assert dt3 is not None
    # Expected: 2024-03-10 13:45:30 UTC
    assert dt3 == datetime.datetime(2024, 3, 10, 13, 45, 30, tzinfo=datetime.timezone.utc)

    # Scenario 4: Valid 'created' string
    entry4 = MockFeedEntry(title="Entry 4", link="http://example.com/4", created="2024-04-05 08:00:00") # Assuming naive is UTC
    dt4 = feed_service.parse_published_time(entry4)
    assert dt4 is not None
    assert dt4 == datetime.datetime(2024, 4, 5, 8, 0, 0, tzinfo=datetime.timezone.utc)

    # Scenario 5: Valid 'dc:date' string (from RDF feeds)
    entry5 = MockFeedEntry(title="Entry 5", link="http://example.com/5", **{'dc:date': "2024-05-01T18:00:00Z"})
    dt5 = feed_service.parse_published_time(entry5)
    assert dt5 is not None
    assert dt5 == datetime.datetime(2024, 5, 1, 18, 0, 0, tzinfo=datetime.timezone.utc)

    # Scenario 6: No date information - should fallback to current time
    entry6 = MockFeedEntry(title="Entry 6", link="http://example.com/6")
    before_fallback = datetime.datetime.now(datetime.timezone.utc)
    dt6 = feed_service.parse_published_time(entry6)
    after_fallback = datetime.datetime.now(datetime.timezone.utc)
    assert dt6 is not None
    assert before_fallback <= dt6 <= after_fallback
    assert dt6.tzinfo == datetime.timezone.utc

    # Scenario 7: Invalid date string
    entry7 = MockFeedEntry(title="Entry 7", link="http://example.com/7", published="not a date")
    before_fallback_invalid = datetime.datetime.now(datetime.timezone.utc)
    dt7 = feed_service.parse_published_time(entry7)
    after_fallback_invalid = datetime.datetime.now(datetime.timezone.utc)
    assert dt7 is not None
    assert before_fallback_invalid <= dt7 <= after_fallback_invalid
    assert dt7.tzinfo == datetime.timezone.utc


def test_kernel_org_scenario(db_setup, mocker):
    """Test Kernel.org scenario: multiple items with unique GUIDs but same link in one batch."""
    logger.info("Testing Kernel.org scenario (unique GUIDs, same link)")
    app = db_setup # Get app from fixture

    # Mock feedparser.parse
    entry1 = MockFeedEntry(title="Kernel 1", link="https://www.kernel.org/", guid="kernel.guid.1", published="2024-01-01T10:00:00Z")
    entry2 = MockFeedEntry(title="Kernel 2", link="https://www.kernel.org/", guid="kernel.guid.2", published="2024-01-02T10:00:00Z")
    entry3 = MockFeedEntry(title="Kernel 3", link="https://www.kernel.org/", guid="kernel.guid.3", published="2024-01-03T10:00:00Z")
    mock_feed_data = MockParsedFeed(feed_title="Kernel Updates", entries=[entry1, entry2, entry3])

    # Mock requests.get to return a dummy response
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    # Mock feedparser.parse to return our mock feed data directly since we are mocking requests
    mocker.patch('backend.feed_service.feedparser.parse', return_value=mock_feed_data)

    # Add a feed to the DB
    tab = Tab(name="Tech", order=1)
    db.session.add(tab)
    db.session.commit()
    feed_obj = Feed(name="Kernel Org Feed", url="http://dummy.kernel.org/feed", tab_id=tab.id)
    db.session.add(feed_obj)
    db.session.commit()

    # Process entries
    new_items_count = feed_service.process_feed_entries(feed_obj, mock_feed_data)

    assert new_items_count == 1, "Should add only the first item as they all have the same link"

    items_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).all()
    assert len(items_in_db) == 1
    guids_in_db = {item.guid for item in items_in_db}
    assert guids_in_db == {"https://www.kernel.org/"}
    links_in_db = {item.link for item in items_in_db}
    assert links_in_db == {"https://www.kernel.org/"} # All share the same link


def test_hacker_news_scenario_guid_handling(db_setup, mocker):
    """Test Hacker News scenario: items with no true GUID (feedparser uses link as id)."""
    logger.info("Testing Hacker News scenario (link-as-ID handling)")
    app = db_setup

    # feedparser might set entry.id = entry.link if no <guid> is present
    entry1 = MockFeedEntry(title="HN Story 1", link="http://news.example.com/item1", guid="http://news.example.com/item1", published="2024-01-01T10:00:00Z")
    entry2 = MockFeedEntry(title="HN Story 2", link="http://news.example.com/item2", guid="http://news.example.com/item2", published="2024-01-02T10:00:00Z")
    # Entry 3 has a *true* GUID
    entry3 = MockFeedEntry(title="HN Story 3 TrueGUID", link="http://news.example.com/item3", guid="true.guid.story3", published="2024-01-03T10:00:00Z")

    mock_feed_data = MockParsedFeed(feed_title="HN Mock Feed", entries=[entry1, entry2, entry3])

    # Mock requests.get
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    mocker.patch('backend.feed_service.feedparser.parse', return_value=mock_feed_data)

    tab = Tab(name="News", order=1)
    db.session.add(tab)
    db.session.commit()
    feed_obj = Feed(name="HN Feed", url="http://dummy.hn.org/feed", tab_id=tab.id)
    db.session.add(feed_obj)
    db.session.commit()

    new_items_count = feed_service.process_feed_entries(feed_obj, mock_feed_data)
    assert new_items_count == 3

    items_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).order_by(FeedItem.link).all()
    assert len(items_in_db) == 3

    # Items where guid was same as link should have the link in db_guid
    assert items_in_db[0].link == "http://news.example.com/item1"
    assert items_in_db[0].guid == "http://news.example.com/item1"
    assert items_in_db[1].link == "http://news.example.com/item2"
    assert items_in_db[1].guid == "http://news.example.com/item2"
    # Item with a true GUID
    assert items_in_db[2].link == "http://news.example.com/item3"
    assert items_in_db[2].guid == "http://news.example.com/item3"


def test_duplicate_link_same_feed_no_true_guid(db_setup, mocker):
    """Test items with no true GUID but duplicate links in the SAME feed are deduplicated by link."""
    logger.info("Testing duplicate links (no true GUID) in same feed")
    app = db_setup

    entry1 = MockFeedEntry(title="Story A", link="http://example.com/story", guid="http://example.com/story", published="2024-01-01T10:00:00Z") # Link-as-ID
    entry2 = MockFeedEntry(title="Story A Duplicate", link="http://example.com/story", guid="http://example.com/story", published="2024-01-01T10:05:00Z") # Link-as-ID, same link

    mock_feed_data = MockParsedFeed(feed_title="Duplicate Link Feed", entries=[entry1, entry2])

    # Mock requests.get
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    mocker.patch('backend.feed_service.feedparser.parse', return_value=mock_feed_data)

    tab = Tab(name="General", order=1)
    db.session.add(tab)
    db.session.commit()
    feed_obj = Feed(name="Test Feed DupLinks", url="http://dummy.duplinks.org/feed", tab_id=tab.id)
    db.session.add(feed_obj)
    db.session.commit()

    # First processing run
    new_items_count1 = feed_service.process_feed_entries(feed_obj, mock_feed_data)
    assert new_items_count1 == 1, "Should only add the first item due to link deduplication in batch"

    item_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).one()
    assert item_in_db.title == "Story A"
    assert item_in_db.guid == "http://example.com/story" # Stored as link because guid was same as link

    # Simulate fetching again - should not add any new items
    # The existing item has link "http://example.com/story" and guid "http://example.com/story".
    # The incoming items will also resolve to guid None and same link.
    # existing_feed_links will catch it.
    new_items_count2 = feed_service.process_feed_entries(feed_obj, mock_feed_data)
    assert new_items_count2 == 0, "Should not add any items on second fetch due to existing link"
    assert FeedItem.query.filter_by(feed_id=feed_obj.id).count() == 1


def test_per_feed_guid_uniqueness_and_null_guid_behavior(db_setup, mocker):
    """
    Tests that GUIDs are unique on a per-feed basis and that NULL GUIDs from
    different feeds do not conflict.
    """
    logger.info("Testing global GUID uniqueness and NULL GUIDs from different feeds")
    app = db_setup

    # Feed 1
    entry_f1_1 = MockFeedEntry(title="F1 Story 1", link="http://feed1.com/item1", guid="global.guid.1", published="2024-01-01T10:00:00Z") # True GUID
    entry_f1_2 = MockFeedEntry(title="F1 Story 2", link="http://feed1.com/item2", guid="http://feed1.com/item2", published="2024-01-01T11:00:00Z") # Link-as-ID
    mock_feed1_data = MockParsedFeed(feed_title="Feed 1", entries=[entry_f1_1, entry_f1_2])

    # Feed 2
    entry_f2_1 = MockFeedEntry(title="F2 Story 1", link="http://feed2.com/item1", guid="global.guid.1", published="2024-01-02T10:00:00Z") # Duplicate True GUID
    entry_f2_2 = MockFeedEntry(title="F2 Story 2", link="http://feed2.com/item2", guid="http://feed2.com/item2", published="2024-01-02T11:00:00Z") # Link-as-ID, different link from F1S2
    entry_f2_3 = MockFeedEntry(title="F2 Story 3", link="http://feed1.com/item2", guid="http://feed1.com/item2", published="2024-01-02T12:00:00Z") # Link-as-ID, same link as F1S2
                                                                                                                                          # but different feed.
    mock_feed2_data = MockParsedFeed(feed_title="Feed 2", entries=[entry_f2_1, entry_f2_2, entry_f2_3])

    # Mock requests.get
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    m_parse = mocker.patch('backend.feed_service.feedparser.parse')

    tab = Tab(name="Mixed", order=1)
    db.session.add(tab)
    db.session.commit()

    feed1_obj = Feed(name="Feed1", url="http://dummy.feed1/rss", tab_id=tab.id)
    feed2_obj = Feed(name="Feed2", url="http://dummy.feed2/rss", tab_id=tab.id)
    db.session.add_all([feed1_obj, feed2_obj])
    db.session.commit()

    # Process Feed 1
    m_parse.return_value = mock_feed1_data
    count1 = feed_service.process_feed_entries(feed1_obj, mock_feed1_data)
    assert count1 == 2
    f1_items = FeedItem.query.filter_by(feed_id=feed1_obj.id).all()
    assert f1_items[0].guid == "http://feed1.com/item1"
    assert f1_items[1].guid == "http://feed1.com/item2"

    # Process Feed 2
    m_parse.return_value = mock_feed2_data
    count2 = feed_service.process_feed_entries(feed2_obj, mock_feed2_data)

    # Expected for Feed 2 with per-feed GUID uniqueness:
    # entry_f2_1 (link="http://feed2.com/item1") is unique for Feed 2 and should be added.
    # entry_f2_2 (link="http://feed2.com/item2") is unique for Feed 2 and should be added.
    # entry_f2_3 (link="http://feed1.com/item2") is unique for Feed 2 and should be added.
    assert count2 == 3, "All 3 items from Feed 2 should be added with per-feed GUID uniqueness"

    # Check items in Feed 2
    f2_items = FeedItem.query.filter_by(feed_id=feed2_obj.id).order_by(FeedItem.published_time).all()
    assert len(f2_items) == 3

    # entry_f2_1
    assert f2_items[0].guid == "http://feed2.com/item1"
    assert f2_items[0].title == "F2 Story 1"
    # entry_f2_2
    assert f2_items[1].guid == "http://feed2.com/item2"
    assert f2_items[1].title == "F2 Story 2"
    # entry_f2_3
    assert f2_items[2].guid == "http://feed1.com/item2"
    assert f2_items[2].title == "F2 Story 3"

    # Verify total items in DB: 2 from Feed1 + 3 from Feed2
    assert FeedItem.query.count() == (count1 + count2)


def test_update_feed_last_updated_time(db_setup, mocker):
    """Test that feed.last_updated_time is updated even if no new items or no entries."""
    logger.info("Testing feed.last_updated_time updates")
    app = db_setup

    tab = Tab(name="Timestamps", order=1)
    db.session.add(tab)
    db.session.commit()

    feed_obj = Feed(name="TestTimestampFeed", url="http://dummy.timestamp/rss", tab_id=tab.id)
    # Create initial_time as naive UTC to match DB retrieval behavior
    initial_time_aware = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    initial_time_naive = initial_time_aware.replace(tzinfo=None)

    # When setting, SQLAlchemy handles the aware datetime for the default
    # but if we set it directly for the test, make it aware so it's stored as UTC.
    # The default lambda in the model makes it aware.
    feed_obj.last_updated_time = initial_time_aware
    db.session.add(feed_obj)
    db.session.commit()
    # After commit and refresh, last_updated_time will be naive from SQLite
    db.session.refresh(feed_obj)
    assert feed_obj.last_updated_time == initial_time_naive, "Initial time setup check"

    # Mock requests.get
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    # Scenario 1: Fetch successful, but no entries in the feed
    mock_empty_feed = MockParsedFeed(feed_title="Empty Feed", entries=[])
    mocker.patch('backend.feed_service.feedparser.parse', return_value=mock_empty_feed)

    feed_service.fetch_and_update_feed(feed_obj.id)
    db.session.refresh(feed_obj) # Reload from DB
    # feed_obj.last_updated_time is naive (from DB), initial_time_naive is naive
    assert feed_obj.last_updated_time > initial_time_naive, "last_updated_time should update for empty feed"

    # Scenario 2: Fetch successful, entries exist, but they are all duplicates (0 new items)
    entry_old = MockFeedEntry(title="Old Story", link="http://timestamp.com/old", guid="old.guid", published="2023-01-01T10:00:00Z")
    # Add this item to DB first
    db.session.add(FeedItem(feed_id=feed_obj.id, title=entry_old.title, link=entry_old.link, guid=entry_old.id, published_time=feed_service.parse_published_time(entry_old))) # Changed entry_old.guid to entry_old.id
    db.session.commit()

    time_before_second_update_aware = datetime.datetime.now(datetime.timezone.utc)
    time_before_second_update_naive = time_before_second_update_aware.replace(tzinfo=None)

    # Set last_updated_time to an earlier point (use aware for consistency with how service sets it)
    feed_obj.last_updated_time = time_before_second_update_aware - datetime.timedelta(minutes=10)
    db.session.commit()
    db.session.refresh(feed_obj) # Ensure it's read back as naive

    mock_duplicate_feed = MockParsedFeed(feed_title="Duplicate Feed", entries=[entry_old])
    mocker.patch('backend.feed_service.feedparser.parse', return_value=mock_duplicate_feed)

    success, new_items = feed_service.fetch_and_update_feed(feed_obj.id)
    assert success is True
    assert new_items == 0
    db.session.refresh(feed_obj)
    assert feed_obj.last_updated_time > time_before_second_update_naive, "last_updated_time should update even if 0 new items"


def test_update_all_feeds_basic_run(db_setup, mocker):
    """Basic test for update_all_feeds to ensure it runs and updates counts."""
    logger.info("Testing update_all_feeds() basic run")
    app = db_setup

    # Mock feedparser.parse to return some basic feeds
    mock_feed_data1 = MockParsedFeed("Feed A", [MockFeedEntry("A1","http://a.com/1","gA1")])
    mock_feed_data2 = MockParsedFeed("Feed B", [MockFeedEntry("B1","http://b.com/1","gB1"), MockFeedEntry("B2","http://b.com/2","gB2")])

    # Mock requests.get
    mock_response = mocker.Mock()
    mock_response.content = b""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch('backend.feed_service.requests.get', return_value=mock_response)

    m_parse = mocker.patch('backend.feed_service.feedparser.parse')

    # Add feeds
    tab = Tab(name="TestTab", order=0)
    db.session.add(tab)
    db.session.commit()
    feed1 = Feed(name="FeedA_init", url="http://feedA.url", tab_id=tab.id)
    feed2 = Feed(name="FeedB_init", url="http://feedB.url", tab_id=tab.id)
    db.session.add_all([feed1, feed2])
    db.session.commit()

    # Side effect for multiple calls to parse
    m_parse.side_effect = [mock_feed_data1, mock_feed_data2]

    processed, new_items = feed_service.update_all_feeds()

    assert processed == 2, "Should process both feeds"
    assert new_items == 3, "Should add 1 from FeedA and 2 from FeedB"

    assert FeedItem.query.count() == 3
    feed1_db = Feed.query.filter_by(url="http://feedA.url").first()
    feed2_db = Feed.query.filter_by(url="http://feedB.url").first()
    assert feed1_db.name == "Feed A" # Check title update
    assert feed2_db.name == "Feed B"


def test_integrity_error_fallback_to_individual_commits(db_setup, mocker):
    """
    Test that if a batch insert fails due to IntegrityError, the system falls back
    to inserting items individually, and valid items are still added.
    """
    logger.info("Testing IntegrityError fallback to individual commits")
    app = db_setup

    tab = Tab(name="Test Tab Fallback", order=0)
    db.session.add(tab)
    db.session.commit()

    feed_obj = Feed(name="Fallback Test Feed", url="http://fallback.com/rss", tab_id=tab.id)
    db.session.add(feed_obj)
    db.session.commit()

    # Prepare two valid items that would normally be batch inserted.
    entry1 = MockFeedEntry(title="Fallback Item 1", link="http://fallback.com/item1", guid="fb-guid1", published="2024-03-01T10:00:00Z")
    entry2 = MockFeedEntry(title="Fallback Item 2", link="http://fallback.com/item2", guid="fb-guid2", published="2024-03-02T10:00:00Z")
    mock_feed_data = MockParsedFeed(feed_title="Fallback Data", entries=[entry1, entry2])

    # Spy on loggers
    warning_spy = mocker.spy(feed_service.logger, 'warning')
    error_spy = mocker.spy(feed_service.logger, 'error') # To check no individual errors for valid items

    # Mock db.session.commit: first call (batch) raises IntegrityError, subsequent calls (individual) succeed.
    # Need to handle the commit for updating feed's last_updated_time after batch failure as well.
    mock_commit = mocker.patch.object(db.session, 'commit')

    # Sequence of commit behaviors:
    # 1. Batch item insert (fails)
    # 2. Update last_updated_time for feed (succeeds)
    # 3. Individual insert item 1 (succeeds)
    # 4. Individual insert item 2 (succeeds)
    mock_commit.side_effect = [
        IntegrityError("Mocked Batch IntegrityError", params=None, orig=None), # Batch item insert fails
        None,  # Commit for feed.last_updated_time
        None,  # Individual commit for item 1
        None   # Individual commit for item 2
    ]

    new_items_count = feed_service.process_feed_entries(feed_obj, mock_feed_data)

    assert new_items_count == 2, "Both items should have been added individually"

    # Verify items in DB (though commit is mocked, check if they would have been added to session)
    # More importantly, check logs.
    items_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).all()
    # Because the actual commit is mocked to succeed for individuals, items should be in DB.
    assert len(items_in_db) == 2
    item_titles = {item.title for item in items_in_db}
    assert "Fallback Item 1" in item_titles
    assert "Fallback Item 2" in item_titles

    # Check for the batch failure warning
    warning_found = any(
        "Batch insert failed" in call.args[0] and f"feed '{feed_obj.name}'" in call.args[0]
        for call in warning_spy.call_args_list
    )
    assert warning_found, "Should log a warning about batch insert failure"

    # Check that there are NO "Failed to individually add item" errors for these valid items
    individual_error_found = any(
        "Failed to individually add item" in call.args[0]
        for call in error_spy.call_args_list
    )
    assert not individual_error_found, "Should not log errors for individually added valid items"


# Keep existing test_update_all_feeds, but rename it to avoid clash if it was meant to be different
def test_original_update_all_feeds_empty_db(db_setup):
    """Test updating all feeds in an empty database"""
    logger.info("Testing update_all_feeds() on an empty DB")
    app = db_setup # Ensures app context

    feeds_updated, new_items = feed_service.update_all_feeds()
    logger.info(f"Updated {feeds_updated} feeds, added {new_items} new items")
    
    assert feeds_updated == 0
    assert new_items == 0

# Note: The original test_fetch_feed is skipped as it's for manual URL testing.
# The original add_test_feed is a helper, not a test. It's used implicitly by some manual test setups.
# For automated tests, it's better to set up DB state directly or use mocks as above.


def test_feed_item_eviction_on_limit_exceeded(db_setup, mocker):
    """
    Test that when a feed exceeds the MAX_ITEMS_PER_FEED limit, the oldest items are evicted.
    """
    logger.info("Testing feed item eviction logic")
    app = db_setup

    tab = Tab(name="Eviction Test Tab", order=0)
    db.session.add(tab)
    db.session.commit()

    feed_obj = Feed(name="Eviction Test Feed", url="http://eviction.com/rss", tab_id=tab.id)
    db.session.add(feed_obj)
    db.session.commit()

    # 1. Add 110 mock items to the database directly to simulate an existing large feed
    for i in range(110):
        # Stagger published times to have a clear order
        pub_time = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc) + datetime.timedelta(minutes=i)
        item = FeedItem(
            feed_id=feed_obj.id,
            title=f"Old Item {i}",
            link=f"http://eviction.com/item{i}",
            guid=f"guid{i}",
            published_time=pub_time
        )
        db.session.add(item)
    db.session.commit()

    assert db.session.query(FeedItem).filter_by(feed_id=feed_obj.id).count() == 110, "Pre-condition: Feed should have 110 items"

    # 2. Prepare a new feed fetch that adds 5 more items
    new_entries = []
    for i in range(5):
        pub_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=i)
        new_entries.append(
            MockFeedEntry(title=f"New Item {i}", link=f"http://eviction.com/new{i}", guid=f"new-guid{i}", published=pub_time.isoformat())
        )
    mock_feed_data = MockParsedFeed(feed_title="Eviction Data", entries=new_entries)

    # 3. Call process_feed_entries, which should add new items AND trigger eviction
    new_items_count = feed_service.process_feed_entries(feed_obj, mock_feed_data)

    assert new_items_count == 5, "Should add the 5 new items"

    # 4. Verify the total number of items is now back down to the limit (100)
    final_item_count = db.session.query(FeedItem).filter_by(feed_id=feed_obj.id).count()
    assert final_item_count == 100, "Feed should have exactly 100 items after eviction"

    # 5. Verify that the items that remain are the newest ones
    oldest_remaining_item = db.session.query(FeedItem).filter_by(feed_id=feed_obj.id).order_by(FeedItem.published_time.asc()).first()
    newest_remaining_item = db.session.query(FeedItem).filter_by(feed_id=feed_obj.id).order_by(FeedItem.published_time.desc()).first()

    assert "Old Item" in oldest_remaining_item.title # Check that some old items remain
    assert "New Item" in newest_remaining_item.title # Check that the new items are present

    # The titles of the first 15 old items (0-14) should have been deleted (110 + 5 - 100 = 15)
    deleted_item_titles = {f"Old Item {i}" for i in range(15)}
    remaining_titles = {item.title for item in db.session.query(FeedItem).filter_by(feed_id=feed_obj.id).all()}
    assert not deleted_item_titles.intersection(remaining_titles), "The oldest 15 items should have been deleted"
