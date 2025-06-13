import pytest
import datetime
from datetime import timezone # Ensure timezone is imported
import time
from unittest.mock import MagicMock, patch, call, ANY
from collections import namedtuple
from sqlalchemy.exc import IntegrityError

from .feed_service import parse_published_time, fetch_feed, process_feed_entries, fetch_and_update_feed, update_all_feeds
from .app import app # For app context
from .models import db, Feed, FeedItem # For spec and type hints primarily

# --- Tests for parse_published_time ---

def test_parse_published_time_with_parsed_struct():
    entry = MagicMock()
    parsed_time_struct = time.struct_time((2024, 4, 20, 10, 30, 0, 5, 111, 0)) # feedparser.parse usually gives UTC
    entry.published_parsed = parsed_time_struct
    # published_parsed is assumed to be UTC if naive
    expected_datetime = datetime.datetime(2024, 4, 20, 10, 30, 0, tzinfo=timezone.utc)
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_with_published_field():
    entry = MagicMock()
    entry.published_parsed = None # Ensure this path is not taken
    entry.published = "Sat, 20 Apr 2024 11:00:00 GMT" # Explicitly GMT (UTC)
    # Ensure other fields are not present to avoid interference
    del entry.updated
    del entry.created
    expected_datetime = datetime.datetime(2024, 4, 20, 11, 0, 0, tzinfo=timezone.utc)
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_with_updated_field():
    entry = MagicMock()
    entry.published_parsed = None # Ensure this path is not taken
    del entry.published # Ensure this path is not taken
    entry.updated = "2024-04-20T12:30:45Z" # 'Z' indicates UTC
    del entry.created # Ensure this path is not taken
    expected_datetime = datetime.datetime(2024, 4, 20, 12, 30, 45, tzinfo=timezone.utc)
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_naive_datetime_string():
    entry = MagicMock()
    entry.published_parsed = None
    del entry.updated
    del entry.created
    entry.published = "2024-04-20 10:00:00" # Naive datetime string, should be assumed UTC
    expected_datetime = datetime.datetime(2024, 4, 20, 10, 0, 0, tzinfo=timezone.utc)
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_non_utc_timezone_string():
    entry = MagicMock()
    entry.published_parsed = None
    del entry.updated
    del entry.created
    entry.published = "2024-04-20 12:00:00+02:00" # Datetime string with non-UTC timezone
    expected_datetime = datetime.datetime(2024, 4, 20, 10, 0, 0, tzinfo=timezone.utc) # Expected after conversion to UTC
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_no_valid_field():
    entry = MagicMock()
    entry.published_parsed = None
    # Ensure all relevant fields are unset or do not exist on the mock
    if hasattr(entry, 'published'): del entry.published
    if hasattr(entry, 'updated'): del entry.updated
    if hasattr(entry, 'created'): del entry.created
    # Configure entry.get to return None for these fields if accessed
    def side_effect_get(key, default=None):
        if key in ['published', 'updated', 'created']:
            return None
        return getattr(entry, key, default) # Default behavior for other keys
    entry.get.side_effect = side_effect_get
    assert parse_published_time(entry) is None

# @pytest.mark.skip(reason="Temporarily skipped due to causing CI runner crashes") # Unskipping this test
def test_parse_published_time_invalid_date_string():
    entry = MagicMock()
    entry.published_parsed = None
    entry.published = "not a real date"
    entry.updated = "invalid date format"
    # Ensure other fields are not present
    del entry.created
    assert parse_published_time(entry) is None

# --- Tests for fetch_feed ---

@patch('backend.feed_service.feedparser.parse')
def test_fetch_feed_success(mock_feedparser_parse):
    feed_url = "http://example.com/rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0
    mock_parsed_feed.entries = [MagicMock()]
    mock_feedparser_parse.return_value = mock_parsed_feed
    result = fetch_feed(feed_url)
    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result == mock_parsed_feed

@patch('backend.feed_service.feedparser.parse')
def test_fetch_feed_bozo_exception(mock_feedparser_parse):
    feed_url = "http://example.com/bad_rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 1
    mock_parsed_feed.bozo_exception = "Some parsing error"
    mock_parsed_feed.entries = []
    mock_feedparser_parse.return_value = mock_parsed_feed
    result = fetch_feed(feed_url)
    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result == mock_parsed_feed

@patch('backend.feed_service.feedparser.parse')
def test_fetch_feed_no_entries(mock_feedparser_parse):
    feed_url = "http://example.com/empty_rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0
    mock_parsed_feed.entries = []
    mock_feedparser_parse.return_value = mock_parsed_feed
    result = fetch_feed(feed_url)
    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result == mock_parsed_feed

@patch('backend.feed_service.feedparser.parse')
def test_fetch_feed_exception(mock_feedparser_parse):
    feed_url = "http://example.com/error_rss"
    mock_feedparser_parse.side_effect = Exception("Network error")
    result = fetch_feed(feed_url)
    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result is None

# --- Helper for creating mock entries ---
def create_mock_entry(id=None, link=None, title=None, published=None):
    entry = MagicMock()
    # Explicitly set attributes that a feedparser entry might have.
    # Set to None if not provided.
    entry.id = id
    entry.link = link
    entry.title = title
    entry.published = published
    entry.published_parsed = None # For simplicity, we primarily test string parsing.
    entry.updated = None
    entry.created = None

    # A safe side_effect for the .get() method that doesn't use getattr on the mock.
    def get_side_effect(key, default=None):
        if hasattr(entry, key):
            return getattr(entry, key)
        return default
    entry.get.side_effect = get_side_effect

    return entry

# --- Fixture for tests needing DB setup for feed_service ---
@pytest.fixture
def feed_service_db_setup():
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()

# --- Tests for process_feed_entries ---
@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_new_items(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    mock_feed_db = MagicMock(spec=Feed)
    mock_feed_db.id = 1
    mock_feed_db.name = "Test Feed"
    parsed_feed = MagicMock()
    parsed_feed.entries = [
        create_mock_entry(id="guid1", link="link1", title="Title 1", published="2024-04-20T10:00:00Z"),
        create_mock_entry(id="guid2", link="link2", title="Title 2", published="2024-04-20T11:00:00Z"),
    ]
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query
    
    mock_item_instances = [MagicMock(), MagicMock()]
    MockFeedItemInService.side_effect = mock_item_instances

    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    assert new_count == 2
    # Check that query for existing items was called
    mock_db_session_in_service.query.assert_called_once_with(MockFeedItemInService.guid, MockFeedItemInService.link)
    mock_db_session_in_service.query().filter_by.assert_called_once_with(feed_id=mock_feed_db.id)
    assert MockFeedItemInService.call_count == 2
    MockFeedItemInService.assert_has_calls([
        call(feed_id=1, title='Title 1', link='link1', published_time=datetime.datetime(2024, 4, 20, 10, 0, 0, tzinfo=timezone.utc), is_read=False, guid='guid1'),
        call(feed_id=1, title='Title 2', link='link2', published_time=datetime.datetime(2024, 4, 20, 11, 0, 0, tzinfo=timezone.utc), is_read=False, guid='guid2')
    ], any_order=False)
    mock_db_session_in_service.add.assert_has_calls([call(mock_item_instances[0]), call(mock_item_instances[1])])
    assert mock_feed_db.last_updated_time is not None 
    mock_db_session_in_service.commit.assert_called_once()
    mock_db_session_in_service.rollback.assert_not_called()

@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_duplicate_items(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    """Verify that entries that already exist in the database are not added again."""
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    # One entry is a duplicate by guid, one is a duplicate by link, one is new.
    parsed_feed.entries = [
        create_mock_entry(id="guid1", link="link1", title="Title 1 (dup guid)"),
        create_mock_entry(id="guid2", link="link2", title="Title 2 (dup link)"),
        create_mock_entry(id="guid3", link="link3", title="Title 3 (new)"),
    ]
    
    # Mock the query to return existing items.
    # Use a namedtuple to simulate SQLAlchemy's KeyedTuple, which allows attribute access.
    Row = namedtuple('Row', ['guid', 'link'])
    mock_query = MagicMock()
    mock_query.all.return_value = [
        Row(guid='guid1', link='some_other_link'),
        Row(guid='some_other_guid', link='link2')
    ]
    # This chain mocks `db.session.query(FeedItem.guid, FeedItem.link).filter_by(...)`
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query

    mock_new_item = MagicMock(spec=FeedItem)
    # Only one new item should be created.
    MockFeedItemInService.return_value = mock_new_item

    # ACTION
    new_count = process_feed_entries(mock_feed_db, parsed_feed)
    
    # ASSERT
    assert new_count == 1
    # Only the new item is instantiated.
    MockFeedItemInService.assert_called_once_with(
        feed_id=1,
        title='Title 3 (new)',
        link='link3',
        published_time=None,
        is_read=False,
        guid='guid3'
    )
    # And only that new item is added to the session.
    mock_db_session_in_service.add.assert_called_once_with(mock_new_item)
    mock_db_session_in_service.commit.assert_called_once()
    mock_db_session_in_service.rollback.assert_not_called()

@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_no_guid_or_link(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    """Verify that entries with no guid or link are skipped."""
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    # One entry is invalid (no id/link), the other is valid.
    parsed_feed.entries = [
        create_mock_entry(id=None, link=None, title="Title Missing ID/Link"),
        create_mock_entry(id="guid1", link="link1", title="Title OK"),
    ]
    
    # Mock the query to return no existing items.
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query

    mock_new_item = MagicMock(spec=FeedItem)
    # The FeedItem constructor is only called for the valid entry.
    MockFeedItemInService.return_value = mock_new_item

    # ACTION
    new_count = process_feed_entries(mock_feed_db, parsed_feed)
    
    # ASSERT
    assert new_count == 1
    # Check that FeedItem was called correctly for the one valid item.
    MockFeedItemInService.assert_called_once_with(
        feed_id=1,
        title='Title OK',
        link='link1',
        published_time=None,
        is_read=False,
        guid='guid1'
    )
    # Check that the one created item was added to the session.
    mock_db_session_in_service.add.assert_called_once_with(mock_new_item)
    mock_db_session_in_service.commit.assert_called_once()
    mock_db_session_in_service.rollback.assert_not_called()

@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_commit_error(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    """Verify that a database commit error is handled by rolling back the session."""
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    # One valid new entry to be added.
    parsed_feed.entries = [create_mock_entry(id="guid1", link="link1", title="Title 1")]
    
    # Mock the query to find no existing items.
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query

    mock_new_item = MagicMock(spec=FeedItem)
    MockFeedItemInService.return_value = mock_new_item

    # Mock the commit call to raise an exception.
    mock_db_session_in_service.commit.side_effect = IntegrityError("Mocked DB error", params=None, orig=None)
    
    # ACTION
    new_count = process_feed_entries(mock_feed_db, parsed_feed)
    
    # ASSERT
    # The count of successfully added items should be 0 because of the error.
    assert new_count == 0
    # An item was instantiated and added to the session before the failed commit.
    MockFeedItemInService.assert_called_once()
    mock_db_session_in_service.add.assert_called_once_with(mock_new_item)
    # The session commit was attempted.
    mock_db_session_in_service.commit.assert_called_once()
    # The session should have been rolled back upon error.
    mock_db_session_in_service.rollback.assert_called_once()


@patch('backend.feed_service.db.session')
@patch('backend.feed_service.logger')
def test_process_feed_entries_updates_feed_title(mock_logger, mock_db_session, feed_service_db_setup):
    """Verify that the feed's name is updated if a new title is found in the feed data."""
    # To correctly mock an object with attributes, create the mock first
    # and then set its attributes directly.
    mock_feed_db = MagicMock(spec=Feed)
    mock_feed_db.id = 1
    mock_feed_db.name = "Old Feed Name"

    parsed_feed = MagicMock()
    parsed_feed.entries = [] # No entries needed for this test

    # Mock parsed_feed to have a feed attribute with a new title.
    # The feed's 'feed' attribute is a dict-like object.
    # Using a real dictionary's get method as the side_effect is a robust pattern.
    parsed_feed.feed = MagicMock()
    parsed_feed.feed.get.side_effect = {'title': "New Feed Name"}.get

    # Mock the DB query for existing items to return nothing
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_db_session.query.return_value.filter_by.return_value = mock_query

    # ACTION
    process_feed_entries(mock_feed_db, parsed_feed)

    # ASSERT
    assert mock_feed_db.name == "New Feed Name"
    mock_logger.info.assert_any_call("Updating feed title for 'Old Feed Name' to 'New Feed Name'")
    mock_db_session.commit.assert_called_once()


@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_duplicate_link_new_guid(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    """Verify that an entry with a new GUID but existing link is treated as a duplicate."""
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    # This entry has a new GUID but a link that already exists in the DB.
    parsed_feed.entries = [
        create_mock_entry(id="new_guid", link="existing_link", title="This is a duplicate"),
    ]

    # Mock query to return the existing item's identifiers
    Row = namedtuple('Row', ['guid', 'link'])
    mock_query = MagicMock()
    mock_query.all.return_value = [Row(guid='old_guid', link='existing_link')]
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query

    # ACTION
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # ASSERT
    assert new_count == 0
    MockFeedItemInService.assert_not_called()
    mock_db_session_in_service.add.assert_not_called()
    mock_db_session_in_service.commit.assert_called_once()


@patch('backend.feed_service.db.session')
@patch('backend.feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_case_sensitive_identifiers(MockFeedItemInService, mock_db_session_in_service, feed_service_db_setup):
    """Verify that GUID and link comparisons are case-sensitive."""
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    # Entries whose GUID/link differs only by case from existing ones.
    parsed_feed.entries = [
        create_mock_entry(id="GUID1", link="link1", title="New item, case-sensitive guid"),
        create_mock_entry(id="guid2", link="LINK2", title="New item, case-sensitive link"),
    ]

    # Mock DB returns the lowercase versions.
    Row = namedtuple('Row', ['guid', 'link'])
    mock_query = MagicMock()
    mock_query.all.return_value = [Row(guid='guid1', link='some_link'), Row(guid='some_guid', link='link2')]
    mock_db_session_in_service.query.return_value.filter_by.return_value = mock_query

    mock_item_instances = [MagicMock(), MagicMock()]
    MockFeedItemInService.side_effect = mock_item_instances
    
    # ACTION
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # ASSERT
    assert new_count == 2
    assert MockFeedItemInService.call_count == 2
    mock_db_session_in_service.add.assert_has_calls([call(mock_item_instances[0]), call(mock_item_instances[1])])
    mock_db_session_in_service.commit.assert_called_once()


# --- Tests for fetch_and_update_feed ---

@patch('backend.feed_service.process_feed_entries')
@patch('backend.feed_service.fetch_feed')
@patch('backend.feed_service.db.session.get')
def test_fetch_and_update_feed_success(mock_db_get, mock_fs_fetch_feed, mock_fs_process_feed_entries, feed_service_db_setup):
    feed_id = 1
    mock_feed_instance = MagicMock(spec=Feed)
    mock_feed_instance.id = feed_id
    mock_feed_instance.url = "http://example.com/rss"
    mock_feed_instance.name = "Old Name"
    mock_db_get.return_value = mock_feed_instance

    mock_parsed_feed = MagicMock()
    mock_parsed_feed.feed.get.return_value = "New Feed Title" # Example of getting feed metadata
    mock_parsed_feed.entries = [MagicMock()] # Example, content doesn't matter for this test focus
    mock_fs_fetch_feed.return_value = mock_parsed_feed

    mock_fs_process_feed_entries.return_value = 5 # Assume 5 new items processed

    success, new_items_count = fetch_and_update_feed(feed_id)

    mock_db_get.assert_called_once_with(Feed, feed_id)
    mock_fs_fetch_feed.assert_called_once_with(mock_feed_instance.url)
    mock_fs_process_feed_entries.assert_called_once_with(mock_feed_instance, mock_parsed_feed)
    assert success is True
    assert new_items_count == 5

@patch('backend.feed_service.db.session.get')
def test_fetch_and_update_feed_not_found(mock_db_get, feed_service_db_setup):
    feed_id = 999
    mock_db_get.return_value = None
    success, new_items_count = fetch_and_update_feed(feed_id)
    assert success is False
    assert new_items_count == 0
    mock_db_get.assert_called_once_with(Feed, feed_id)

@patch('backend.feed_service.logger')
@patch('backend.feed_service.fetch_feed')
@patch('backend.feed_service.db.session.get')
def test_fetch_and_update_feed_fetch_error(mock_db_get, mock_fs_fetch_feed, mock_fs_logger, feed_service_db_setup):
    feed_id = 1
    mock_feed_instance = MagicMock(spec=Feed)
    mock_feed_instance.id = feed_id
    mock_feed_instance.url = "http://example.com/broken_rss"
    mock_feed_instance.name = "Broken Test Feed"
    mock_db_get.return_value = mock_feed_instance

    mock_fs_fetch_feed.return_value = None # Simulate fetch failure

    success, new_items_count = fetch_and_update_feed(feed_id)

    mock_db_get.assert_called_once_with(Feed, feed_id)
    mock_fs_fetch_feed.assert_called_once_with(mock_feed_instance.url)
    expected_log_message = f"Fetching content for feed {mock_feed_instance.name} (ID: {feed_id}) failed because fetch_feed returned None."
    mock_fs_logger.error.assert_any_call(expected_log_message)
    assert success is False
    assert new_items_count == 0

@patch('backend.feed_service.logger')
@patch('backend.feed_service.process_feed_entries')
@patch('backend.feed_service.fetch_feed')
@patch('backend.feed_service.db.session.get')
def test_fetch_and_update_feed_process_entries_error(
    mock_db_get, mock_fetch_feed, mock_process_entries, mock_logger, feed_service_db_setup
):
    """Verify that fetch_and_update_feed handles exceptions from process_feed_entries."""
    feed_id = 1
    mock_feed_instance = MagicMock(spec=Feed, id=feed_id, url="http://example.com/rss", name="Test Feed")
    mock_db_get.return_value = mock_feed_instance

    mock_parsed_feed = MagicMock()
    mock_fetch_feed.return_value = mock_parsed_feed

    # Mock process_feed_entries to raise an unexpected exception.
    error_message = "Unexpected processing error"
    mock_process_entries.side_effect = Exception(error_message)

    # ACTION
    success, new_items_count = fetch_and_update_feed(feed_id)

    # ASSERT
    assert success is False
    assert new_items_count == 0
    mock_db_get.assert_called_once_with(Feed, feed_id)
    mock_fetch_feed.assert_called_once_with(mock_feed_instance.url)
    mock_process_entries.assert_called_once_with(mock_feed_instance, mock_parsed_feed)
    mock_logger.error.assert_any_call(
        f"An unexpected error occurred during entry processing for feed {mock_feed_instance.name} (ID: {feed_id}): {error_message}",
        exc_info=True
    )

# --- Tests for update_all_feeds ---

@patch('backend.feed_service.logger')
@patch('backend.feed_service.fetch_and_update_feed')
@patch('backend.feed_service.Feed')
def test_update_all_feeds_success(MockFsFeed, mock_fs_fetch_and_update, mock_fs_logger, feed_service_db_setup):
    with app.app_context():
        mock_feed1 = MagicMock(spec=Feed, id=1, name="Feed 1")
        mock_feed2 = MagicMock(spec=Feed, id=2, name="Feed 2")
    MockFsFeed.query.all.return_value = [mock_feed1, mock_feed2]
    def side_effect_success(feed_id_param):
        if feed_id_param == mock_feed1.id: return (True, 1)
        elif feed_id_param == mock_feed2.id: return (True, 0)
        return (False, 0)
    mock_fs_fetch_and_update.side_effect = side_effect_success
    with app.app_context():
        update_all_feeds()
    MockFsFeed.query.all.assert_called_once()
    assert mock_fs_fetch_and_update.call_count == 2
    mock_fs_fetch_and_update.assert_any_call(mock_feed1.id)
    mock_fs_fetch_and_update.assert_any_call(mock_feed2.id)
    mock_fs_logger.info.assert_any_call("Starting update process for 2 feeds.")
    mock_fs_logger.info.assert_any_call("Finished updating all feeds. Processed: 2, New Items: 1")

@patch('backend.feed_service.logger')
@patch('backend.feed_service.fetch_and_update_feed')
@patch('backend.feed_service.Feed')
def test_update_all_feeds_no_feeds(MockFsFeed, mock_fs_fetch_and_update, mock_fs_logger, feed_service_db_setup):
    MockFsFeed.query.all.return_value = []
    with app.app_context():
        update_all_feeds()
    MockFsFeed.query.all.assert_called_once()
    mock_fs_fetch_and_update.assert_not_called()
    mock_fs_logger.info.assert_any_call("Starting update process for 0 feeds.")
    mock_fs_logger.info.assert_any_call("Finished updating all feeds. Processed: 0, New Items: 0")

@patch('backend.feed_service.logger')
@patch('backend.feed_service.fetch_and_update_feed')
@patch('backend.feed_service.Feed')
def test_update_all_feeds_error_during_update(MockFsFeed, mock_fs_fetch_and_update, mock_fs_logger, feed_service_db_setup):
    with app.app_context():
        mock_feed1 = MagicMock(spec=Feed, id=1, name="Feed 1")
        mock_feed2 = MagicMock(spec=Feed, id=2, name="Feed 2 (will fail)")
        mock_feed3 = MagicMock(spec=Feed, id=3, name="Feed 3")
    MockFsFeed.query.all.return_value = [mock_feed1, mock_feed2, mock_feed3]
    def fetch_side_effect_error(feed_id_param):
        if feed_id_param == mock_feed1.id: return (True, 1)
        elif feed_id_param == mock_feed2.id: raise Exception("Simulated update error for Feed 2")
        elif feed_id_param == mock_feed3.id: return (True, 0)
        return (False, 0)
    mock_fs_fetch_and_update.side_effect = fetch_side_effect_error
    with app.app_context():
        update_all_feeds()
    MockFsFeed.query.all.assert_called_once()
    assert mock_fs_fetch_and_update.call_count == 3
    mock_fs_fetch_and_update.assert_any_call(mock_feed1.id)
    mock_fs_fetch_and_update.assert_any_call(mock_feed2.id)
    mock_fs_fetch_and_update.assert_any_call(mock_feed3.id)
    mock_fs_logger.info.assert_any_call("Starting update process for 3 feeds.")
    mock_fs_logger.error.assert_any_call(f"Unexpected error updating feed {mock_feed2.name} ({mock_feed2.id}): Simulated update error for Feed 2", exc_info=True)
    mock_fs_logger.info.assert_any_call("Finished updating all feeds. Processed: 2, New Items: 1")
