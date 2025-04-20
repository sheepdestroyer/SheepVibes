import pytest
import datetime
import time
from unittest.mock import MagicMock, patch, call
from sqlalchemy.exc import IntegrityError

# Assuming feed_service.py is in the same directory or accessible via PYTHONPATH
from feed_service import parse_published_time, fetch_feed, process_feed_entries
# Mock database objects needed for process_feed_entries tests later
from app import db, Feed, FeedItem # Need to import for type hints and potential setup

# --- Tests for parse_published_time ---

def test_parse_published_time_with_parsed_struct():
    """Test parsing when feedparser provides published_parsed."""
    entry = MagicMock()
    # Create a time.struct_time tuple (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst)
    parsed_time_struct = time.struct_time((2024, 4, 20, 10, 30, 0, 5, 111, 0))
    entry.published_parsed = parsed_time_struct
    expected_datetime = datetime.datetime(2024, 4, 20, 10, 30, 0)
    assert parse_published_time(entry) == expected_datetime

def test_parse_published_time_with_published_field():
    """Test parsing using the 'published' field via dateutil."""
    entry = MagicMock()
    entry.published_parsed = None # Ensure feedparser didn't parse it
    entry.published = "Sat, 20 Apr 2024 11:00:00 GMT"
    expected_datetime = datetime.datetime(2024, 4, 20, 11, 0, 0)
    # Note: dateutil might add timezone info depending on input. Compare naive for simplicity here.
    parsed_dt = parse_published_time(entry)
    assert parsed_dt.replace(tzinfo=None) == expected_datetime

def test_parse_published_time_with_updated_field():
    """Test parsing using the 'updated' field as fallback."""
    entry = MagicMock()
    entry.published_parsed = None
    del entry.published # Make sure 'published' field doesn't exist
    entry.updated = "2024-04-20T12:30:45Z" # ISO 8601 format
    expected_datetime = datetime.datetime(2024, 4, 20, 12, 30, 45)
    parsed_dt = parse_published_time(entry)
    assert parsed_dt.replace(tzinfo=None) == expected_datetime

def test_parse_published_time_no_valid_field():
    """Test when no recognizable date field is present."""
    entry = MagicMock()
    entry.published_parsed = None
    # Ensure no relevant date attributes exist
    del entry.published
    del entry.updated
    del entry.created 
    assert parse_published_time(entry) is None

def test_parse_published_time_invalid_date_string():
    """Test when date fields contain unparseable strings."""
    entry = MagicMock()
    entry.published_parsed = None
    entry.published = "not a real date"
    entry.updated = "invalid date format"
    assert parse_published_time(entry) is None

# --- Tests for fetch_feed ---

# Use patch to mock feedparser.parse for these tests
@patch('feed_service.feedparser.parse')
def test_fetch_feed_success(mock_feedparser_parse):
    """Test fetch_feed successfully parsing a feed."""
    feed_url = "http://example.com/rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0 # Indicates success
    mock_parsed_feed.entries = [MagicMock()] # Has some entries
    mock_feedparser_parse.return_value = mock_parsed_feed

    result = fetch_feed(feed_url)

    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result == mock_parsed_feed

@patch('feed_service.feedparser.parse')
def test_fetch_feed_bozo_exception(mock_feedparser_parse):
    """Test fetch_feed when feedparser indicates an error (bozo=1)."""
    feed_url = "http://example.com/bad_rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 1
    mock_parsed_feed.bozo_exception = "Some parsing error"
    mock_parsed_feed.entries = [] # Might have no entries on error
    mock_feedparser_parse.return_value = mock_parsed_feed

    result = fetch_feed(feed_url)

    mock_feedparser_parse.assert_called_once_with(feed_url)
    # Should still return the parsed feed object, even with bozo=1
    assert result == mock_parsed_feed
    # Check logs (requires logger configuration/capture in test setup)

@patch('feed_service.feedparser.parse')
def test_fetch_feed_no_entries(mock_feedparser_parse):
    """Test fetch_feed when the feed has no entries."""
    feed_url = "http://example.com/empty_rss"
    mock_parsed_feed = MagicMock()
    mock_parsed_feed.bozo = 0
    mock_parsed_feed.entries = [] # Empty list of entries
    mock_feedparser_parse.return_value = mock_parsed_feed

    result = fetch_feed(feed_url)

    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result == mock_parsed_feed
    # Check logs for warning about no entries

@patch('feed_service.feedparser.parse')
def test_fetch_feed_exception(mock_feedparser_parse):
    """Test fetch_feed when feedparser.parse raises an exception."""
    feed_url = "http://example.com/error_rss"
    mock_feedparser_parse.side_effect = Exception("Network error")

    result = fetch_feed(feed_url)

    mock_feedparser_parse.assert_called_once_with(feed_url)
    assert result is None
    # Check logs for error message

# --- Tests for process_feed_entries ---

# Helper to create mock feedparser entries
def create_mock_entry(id=None, link=None, title=None, published=None):
    entry = MagicMock()
    entry.get.side_effect = lambda key, default=None: getattr(entry, key, default)
    entry.id = id
    entry.link = link
    entry.title = title
    entry.published = published
    # Mock the parsed time structure if needed, or rely on parse_published_time tests
    if published:
        # Simple mock for parsed time based on our helper tests
        try: 
            dt = datetime.datetime.strptime(published, "%Y-%m-%dT%H:%M:%SZ")
            entry.published_parsed = dt.timetuple()
        except ValueError:
             entry.published_parsed = None # Let dateutil handle it
    else:
        entry.published_parsed = None
    return entry

# Patch db session and FeedItem class for these tests
@patch('feed_service.db.session')
@patch('feed_service.FeedItem', new_callable=MagicMock) # Mock the class itself
def test_process_feed_entries_new_items(MockFeedItem, mock_session):
    """Test processing a feed with new, unique items."""
    # Arrange
    mock_feed_db = MagicMock(spec=Feed)
    mock_feed_db.id = 1
    mock_feed_db.name = "Test Feed"
    
    parsed_feed = MagicMock()
    parsed_feed.entries = [
        create_mock_entry(id="guid1", link="link1", title="Title 1", published="2024-04-20T10:00:00Z"),
        create_mock_entry(id="guid2", link="link2", title="Title 2", published="2024-04-20T11:00:00Z"),
    ]
    
    # Mock query for existing items (return none)
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_session.query.return_value.filter_by.return_value = mock_query
    
    # Mock FeedItem constructor calls
    mock_item_instances = [MagicMock(), MagicMock()]
    MockFeedItem.side_effect = mock_item_instances

    # Act
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # Assert
    assert new_count == 2
    # Check that query for existing items was called
    mock_session.query.assert_called_once_with(FeedItem.guid, FeedItem.link)
    mock_session.query().filter_by.assert_called_once_with(feed_id=mock_feed_db.id)
    # Check FeedItem constructor calls
    assert MockFeedItem.call_count == 2
    MockFeedItem.assert_has_calls([
        call(feed_id=1, title='Title 1', link='link1', published_time=datetime.datetime(2024, 4, 20, 10, 0), is_read=False, guid='guid1'),
        call(feed_id=1, title='Title 2', link='link2', published_time=datetime.datetime(2024, 4, 20, 11, 0), is_read=False, guid='guid2')
    ], any_order=False) # Order matters here as they are added sequentially
    # Check items were added to session
    mock_session.add.assert_has_calls([call(mock_item_instances[0]), call(mock_item_instances[1])])
    # Check feed last_updated_time was set
    assert mock_feed_db.last_updated_time is not None 
    # Check commit was called
    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_not_called()

@patch('feed_service.db.session')
@patch('feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_duplicate_items(MockFeedItem, mock_session):
    """Test processing skips items that already exist in the DB or batch."""
    # Arrange
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    
    parsed_feed = MagicMock()
    parsed_feed.entries = [
        create_mock_entry(id="guid1", link="link1", title="Title 1"), # Existing by GUID
        create_mock_entry(id="guid2", link="link2", title="Title 2"), # New
        create_mock_entry(id="guid3", link="link3", title="Title 3"), # Existing by Link
        create_mock_entry(id="guid2", link="link2_alt", title="Title 2 Dup GUID"), # Duplicate GUID in batch
        create_mock_entry(id="guid4", link="link2", title="Title 4 Dup Link"), # Duplicate Link in batch
    ]
    
    # Mock query for existing items
    mock_query = MagicMock()
    # Simulate existing items in DB
    existing_db_item1 = MagicMock(guid="guid1", link="link1_db") 
    existing_db_item3 = MagicMock(guid="guid3_db", link="link3")
    mock_query.all.return_value = [existing_db_item1, existing_db_item3]
    mock_session.query.return_value.filter_by.return_value = mock_query
    
    mock_item_instance = MagicMock()
    MockFeedItem.return_value = mock_item_instance

    # Act
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # Assert
    assert new_count == 1 # Only guid2/link2 should be added
    # Check FeedItem constructor was called only once
    MockFeedItem.assert_called_once_with(feed_id=1, title='Title 2', link='link2', published_time=None, is_read=False, guid='guid2')
    # Check add was called only once
    mock_session.add.assert_called_once_with(mock_item_instance)
    # Check commit was called
    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_not_called()

@patch('feed_service.db.session')
@patch('feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_no_guid_or_link(MockFeedItem, mock_session):
    """Test processing skips items with neither guid nor link."""
    # Arrange
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    parsed_feed.entries = [
        create_mock_entry(id=None, link=None, title="Title Missing ID/Link"),
        create_mock_entry(id="guid1", link="link1", title="Title OK"),
    ]
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_session.query.return_value.filter_by.return_value = mock_query
    mock_item_instance = MagicMock()
    MockFeedItem.return_value = mock_item_instance

    # Act
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # Assert
    assert new_count == 1 # Only the valid item is added
    MockFeedItem.assert_called_once_with(feed_id=1, title='Title OK', link='link1', published_time=None, is_read=False, guid='guid1')
    mock_session.add.assert_called_once_with(mock_item_instance)
    mock_session.commit.assert_called_once()
    mock_session.rollback.assert_not_called()
    # Check logs for warning about skipped item

@patch('feed_service.db.session')
@patch('feed_service.FeedItem', new_callable=MagicMock)
def test_process_feed_entries_commit_error(MockFeedItem, mock_session):
    """Test handling of IntegrityError during session commit."""
    # Arrange
    mock_feed_db = MagicMock(spec=Feed, id=1, name="Test Feed")
    parsed_feed = MagicMock()
    parsed_feed.entries = [create_mock_entry(id="guid1", link="link1", title="Title 1")]
    mock_query = MagicMock()
    mock_query.all.return_value = []
    mock_session.query.return_value.filter_by.return_value = mock_query
    mock_item_instance = MagicMock()
    MockFeedItem.return_value = mock_item_instance
    # Simulate commit failure
    mock_session.commit.side_effect = IntegrityError("Mock IntegrityError", params=None, orig=None)

    # Act
    new_count = process_feed_entries(mock_feed_db, parsed_feed)

    # Assert
    assert new_count == 0 # Should return 0 on commit error
    MockFeedItem.assert_called_once() # Item was created
    mock_session.add.assert_called_once_with(mock_item_instance) # Item was added
    assert mock_feed_db.last_updated_time is not None # Time was set before commit attempt
    mock_session.commit.assert_called_once() # Commit was attempted
    mock_session.rollback.assert_called_once() # Rollback occurred
    # Check logs for error message

# --- Placeholder for fetch_and_update_feed tests ---
# Would involve mocking Feed.query.get and patching fetch_feed/process_feed_entries

# --- Placeholder for update_all_feeds tests ---
# Would involve mocking Feed.query.all and patching fetch_and_update_feed
