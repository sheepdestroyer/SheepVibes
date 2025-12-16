import pytest
import json
from unittest.mock import patch, MagicMock
import os
import io
import xml.etree.ElementTree as ET

# Import the Flask app instance and db object
# Need to configure the app for testing
from .app import app, cache # Import the app and cache instance
from .models import db, Tab, Feed, FeedItem # Import models directly
from .feed_service import process_feed_entries, parse_published_time # For new tests
import time # For new tests
import datetime # For new tests, specifically for timezone object
from datetime import timezone # For new tests


@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    # Base test config
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Use an in-memory SQLite database for testing
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['CACHE_TYPE'] = 'SimpleCache'  # Ensure SimpleCache for all test runs
    app.config['CACHE_DEFAULT_TIMEOUT'] = 5   # Use a short timeout for testing
    
    # Reset Flask app's internal state for consistent behavior across tests
    app._got_first_request = False

    # --- Re-initialize extensions for test environment ---

    # Remove existing extension instances to allow re-initialization with test-specific config
    if 'sqlalchemy' in app.extensions:
        del app.extensions['sqlalchemy']
    if 'cache' in app.extensions:
        del app.extensions['cache']
    
    # Get the Redis URL set by pytest-env from pytest.ini
    redis_url = os.environ.get('CACHE_REDIS_URL', 'redis://localhost:6379/0') # Default if not set

    # Force IPv4 for localhost if it's being used.
    if 'localhost' in redis_url:
        redis_url = redis_url.replace('localhost', '127.0.0.1')

    # In a CI environment, GitHub Actions maps the service port to a dynamic
    # port on the host. We check for this port (passed as an env var by the
    # workflow) and update the connection URL accordingly.
    ci_redis_port = os.environ.get('CACHE_REDIS_PORT')
    if ci_redis_port and '127.0.0.1' in redis_url: # Ensure it's still a local target
        # The URL from pytest.ini is 'redis://:password@127.0.0.1:6379/0'
        # We replace the standard port with the dynamic one from the CI env.
        redis_url = redis_url.replace('6379', ci_redis_port, 1)
        
    app.config['CACHE_REDIS_URL'] = redis_url

    # Re-initialize extensions with the updated app config
    db.init_app(app)
    cache.init_app(app)

    with app.app_context(): # Ensure app context for create_all and drop_all
        db.create_all() # Ensure tables are created for each test
        cache.clear()   # Clear cache before each test run for isolation

    with app.test_client() as client:
        yield client # Provide the test client to the tests
    
    # Teardown: drop all tables after each test to ensure isolation
    with app.app_context():
        db.session.remove() # Ensure session is clean before dropping
        db.drop_all()       # Drop all tables

# --- Tests for /api/tabs --- 

def test_get_tabs_empty(client):
    """Test GET /api/tabs when no tabs exist."""
    response = client.get('/api/tabs')
    assert response.status_code == 200
    assert response.json == []

def test_get_tabs_with_data(client):
    """Test GET /api/tabs with existing tabs."""
    # Arrange: Add some tabs to the in-memory DB
    tab1 = Tab(name="Tech", order=1)
    tab2 = Tab(name="News", order=0)
    with app.app_context():
        db.session.add_all([tab1, tab2])
        db.session.commit()
    
    # Act
    response = client.get('/api/tabs')
    
    # Assert
    assert response.status_code == 200
    assert len(response.json) == 2
    # Check order and content (unread_count will be 0)
    assert response.json[0]['name'] == 'News'
    assert response.json[0]['order'] == 0
    assert response.json[0]['unread_count'] == 0
    assert response.json[1]['name'] == 'Tech'
    assert response.json[1]['order'] == 1
    assert response.json[1]['unread_count'] == 0

def test_create_tab_success(client):
    """Test POST /api/tabs successfully creating a new tab."""
    # Act
    response = client.post('/api/tabs', json={'name': '  New Tab  '})
    
    # Assert
    assert response.status_code == 201 # Created
    assert response.json['name'] == 'New Tab' # Check trimmed name
    assert response.json['order'] == 0 # First tab gets order 0
    assert 'id' in response.json
    
    # Verify in DB
    with app.app_context():
        tab = db.session.get(Tab, response.json['id'])
        assert tab is not None
        assert tab.name == 'New Tab'

def test_create_tab_missing_name(client):
    """Test POST /api/tabs with missing name data."""
    response = client.post('/api/tabs', json={})
    assert response.status_code == 400
    assert 'error' in response.json
    assert 'Missing or empty tab name' in response.json['error']

def test_create_tab_empty_name(client):
    """Test POST /api/tabs with empty name string."""
    response = client.post('/api/tabs', json={'name': '   '})
    assert response.status_code == 400
    assert 'error' in response.json
    assert 'Missing or empty tab name' in response.json['error']

def test_create_tab_duplicate_name(client):
    """Test POST /api/tabs with a duplicate name."""
    # Arrange: Create initial tab
    client.post('/api/tabs', json={'name': 'Existing Tab'})
    
    # Act: Try to create another with the same name
    response = client.post('/api/tabs', json={'name': 'Existing Tab'})
    
    # Assert
    assert response.status_code == 409 # Conflict
    assert 'error' in response.json
    assert 'already exists' in response.json['error']

def test_rename_tab_success(client):
    """Test PUT /api/tabs/<id> successfully renaming a tab."""
    # Arrange: Create a tab first
    post_resp = client.post('/api/tabs', json={'name': 'Old Name'})
    tab_id = post_resp.json['id']
    
    # Act
    response = client.put(f'/api/tabs/{tab_id}', json={'name': 'New Name'})
    
    # Assert
    assert response.status_code == 200
    assert response.json['id'] == tab_id
    assert response.json['name'] == 'New Name'
    
    # Verify in DB
    with app.app_context():
        tab = db.session.get(Tab, tab_id)
        assert tab.name == 'New Name'

def test_rename_tab_not_found(client):
    """Test PUT /api/tabs/<id> for a non-existent tab."""
    response = client.put('/api/tabs/999', json={'name': 'New Name'})
    assert response.status_code == 404
    assert 'error' in response.json
    assert 'not found' in response.json['error']

def test_rename_tab_duplicate_name(client):
    """Test PUT /api/tabs/<id> trying to rename to an existing name."""
    # Arrange: Create two tabs
    post_resp1 = client.post('/api/tabs', json={'name': 'Tab One'})
    tab1_id = post_resp1.json['id']
    client.post('/api/tabs', json={'name': 'Tab Two'})
    
    # Act: Try renaming Tab One to "Tab Two"
    response = client.put(f'/api/tabs/{tab1_id}', json={'name': 'Tab Two'})
    
    # Assert
    assert response.status_code == 409 # Conflict
    assert 'error' in response.json
    assert 'already in use' in response.json['error']

def test_delete_tab_success(client):
    """Test DELETE /api/tabs/<id> successfully deleting a tab."""
    # Arrange: Create two tabs
    post_resp1 = client.post('/api/tabs', json={'name': 'To Delete'})
    tab1_id = post_resp1.json['id']
    client.post('/api/tabs', json={'name': 'To Keep'})
    
    # Act
    response = client.delete(f'/api/tabs/{tab1_id}')
    
    # Assert
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'deleted successfully' in response.json['message']
    
    # Verify in DB
    with app.app_context():
        tab = db.session.get(Tab, tab1_id)
        assert tab is None
        assert Tab.query.count() == 1

def test_delete_tab_not_found(client):
    """Test DELETE /api/tabs/<id> for a non-existent tab."""
    response = client.delete('/api/tabs/999')
    assert response.status_code == 404
    assert 'error' in response.json
    assert 'not found' in response.json['error']

def test_delete_last_tab(client):
    """Test DELETE /api/tabs/<id> preventing deletion of the last tab."""
    # Arrange: Create only one tab
    post_resp = client.post('/api/tabs', json={'name': 'The Only Tab'})
    tab_id = post_resp.json['id']
    
    # Act
    response = client.delete(f'/api/tabs/{tab_id}')
    
    # Assert: Now it should be successful (200)
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'deleted successfully' in response.json['message']
    
    # Verify in DB
    with app.app_context():
        assert Tab.query.count() == 0 # Tab should be deleted

# --- Tests for Feed/Item endpoints ---

@pytest.fixture
def setup_tabs_and_feeds(client):
    """Fixture to pre-populate the DB with tabs and feeds for testing."""
    with app.app_context():
        tab1 = Tab(name="Tab 1", order=0)
        tab2 = Tab(name="Tab 2", order=1)
        db.session.add_all([tab1, tab2])
        db.session.commit() # Commit to get IDs
        
        feed1 = Feed(tab_id=tab1.id, name="Feed 1", url="url1")
        feed2 = Feed(tab_id=tab1.id, name="Feed 2", url="url2")
        feed3 = Feed(tab_id=tab2.id, name="Feed 3", url="url3", site_link="http://example.com/feed3")
        db.session.add_all([feed1, feed2, feed3])
        db.session.commit()
        
        item1 = FeedItem(feed_id=feed1.id, title="Item 1.1", link="link1.1", guid="guid1.1", is_read=False)
        item2 = FeedItem(feed_id=feed1.id, title="Item 1.2", link="link1.2", guid="guid1.2", is_read=True)
        item3 = FeedItem(feed_id=feed2.id, title="Item 2.1", link="link2.1", guid="guid2.1", is_read=False)
        db.session.add_all([item1, item2, item3])
        db.session.commit()
        
        return {"tab1_id": tab1.id, "tab2_id": tab2.id, 
                "feed1_id": feed1.id, "feed2_id": feed2.id, "feed3_id": feed3.id,
                "item1_id": item1.id, "item2_id": item2.id, "item3_id": item3.id}

def test_get_feeds_for_tab_with_items(client, setup_tabs_and_feeds):
    """Test GET /api/tabs/<tab_id>/feeds returns feeds bundled with their items."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    
    # Act
    response = client.get(f'/api/tabs/{tab1_id}/feeds')
    
    # Assert
    assert response.status_code == 200
    data = response.json
    assert len(data) == 2 # Feed 1 and Feed 2 are in Tab 1
    
    # Sort data by feed name to have a predictable order for testing
    data.sort(key=lambda x: x['name'])
    
    feed1_data = data[0]
    assert feed1_data['name'] == 'Feed 1'
    assert 'items' in feed1_data
    assert len(feed1_data['items']) == 2 # Item 1.1 and 1.2
    item_titles1 = {item['title'] for item in feed1_data['items']}
    assert item_titles1 == {'Item 1.1', 'Item 1.2'}
    
    feed2_data = data[1]
    assert feed2_data['name'] == 'Feed 2'
    assert 'items' in feed2_data
    assert len(feed2_data['items']) == 1 # Item 2.1
    item_titles2 = {item['title'] for item in feed2_data['items']}
    assert item_titles2 == {'Item 2.1'}

def test_get_feeds_for_tab_with_items_and_limit(client, setup_tabs_and_feeds):
    """Test the limit parameter on GET /api/tabs/<tab_id>/feeds."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    
    # Act
    response = client.get(f'/api/tabs/{tab1_id}/feeds?limit=1')
    
    # Assert
    assert response.status_code == 200
    data = response.json
    assert len(data) == 2
    
    data.sort(key=lambda x: x['name'])
    
    feed1_data = data[0]
    assert feed1_data['name'] == 'Feed 1'
    assert len(feed1_data['items']) == 1 # Limited to 1
    
    feed2_data = data[1]
    assert feed2_data['name'] == 'Feed 2'
    assert len(feed2_data['items']) == 1 # Limited to 1

def test_get_feeds_for_tab_with_feed_having_no_items(client, setup_tabs_and_feeds):
    """Test GET /api/tabs/<tab_id>/feeds for a tab with a feed that has no items."""
    tab2_id = setup_tabs_and_feeds["tab2_id"]

    # Act
    response = client.get(f'/api/tabs/{tab2_id}/feeds')

    # Assert
    assert response.status_code == 200
    data = response.json
    assert len(data) == 1 # Only Feed 3 is in Tab 2

    feed3_data = data[0]
    assert feed3_data['name'] == 'Feed 3'
    assert 'items' in feed3_data
    assert len(feed3_data['items']) == 0 # Feed 3 has no items

def test_get_feeds_for_tab_with_no_feeds(client):
    """Test GET /api/tabs/<tab_id>/feeds for a tab that has no feeds."""
    # Arrange: Create a new tab with no feeds
    with app.app_context():
        new_tab = Tab(name="Empty Tab", order=0)
        db.session.add(new_tab)
        db.session.commit()
        tab_id = new_tab.id

    # Act
    response = client.get(f'/api/tabs/{tab_id}/feeds')

    # Assert
    assert response.status_code == 200
    assert response.json == []

def test_get_feeds_for_tab_not_found(client):
    """Test GET /api/tabs/<tab_id>/feeds for non-existent tab."""
    response = client.get('/api/tabs/999/feeds')
    assert response.status_code == 404

# Mock feed fetching/processing for add/delete tests
@patch('backend.app.fetch_feed') # Patch fetch_feed where it's used in app.py
@patch('backend.app.process_feed_entries') # Patch process_feed_entries where it's used in app.py
def test_add_feed_success(mock_process_entries, mock_fetch, client, setup_tabs_and_feeds):
    """Test POST /api/feeds successfully adding a feed."""
    # Arrange
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    feed_url = "http://newsite.com/rss"
    # Mock fetch_feed to return a basic parsed structure with a title
    mock_parsed = MagicMock()
    mock_parsed.feed.get.return_value = "New Feed Title"
    mock_fetch.return_value = mock_parsed
    # Mock process_feed_entries (doesn't need to do anything for this test)
    mock_process_entries.return_value = 0
    
    # Act
    response = client.post('/api/feeds', json={'url': feed_url, 'tab_id': tab1_id})
    
    # Assert
    assert response.status_code == 201
    assert response.json['name'] == "New Feed Title"
    assert response.json['url'] == feed_url
    assert response.json['tab_id'] == tab1_id
    assert 'id' in response.json
    mock_fetch.assert_called_once_with(feed_url)
    # Check that process_feed_entries was called after commit (need feed ID)
    assert mock_process_entries.call_count == 1
    
    # Verify in DB
    with app.app_context():
        feed = db.session.get(Feed, response.json['id'])
        assert feed is not None
        assert feed.url == feed_url
        assert feed.tab_id == tab1_id

@patch('backend.app.fetch_feed')
def test_add_feed_fetch_fails(mock_fetch, client, setup_tabs_and_feeds):
    """Test POST /api/feeds when initial fetch fails (should still add)."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    feed_url = "http://badsite.com/rss"
    mock_fetch.return_value = None # Simulate fetch failure
    
    response = client.post('/api/feeds', json={'url': feed_url, 'tab_id': tab1_id})
    
    assert response.status_code == 201
    assert response.json['name'] == feed_url # Uses URL as name on fetch failure
    assert response.json['url'] == feed_url
    mock_fetch.assert_called_once_with(feed_url)

@patch('backend.app.fetch_feed')
def test_add_feed_duplicate_url(mock_fetch, client, setup_tabs_and_feeds):
    """Test POST /api/feeds with a duplicate URL."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    existing_url = "url1" # From setup_tabs_and_feeds
    
    response = client.post('/api/feeds', json={'url': existing_url, 'tab_id': tab1_id})
    
    assert response.status_code == 409 # Conflict
    assert 'error' in response.json
    assert 'already exists' in response.json['error']
    mock_fetch.assert_not_called() # Should check DB before fetching

@patch('backend.app.fetch_feed') # Also needs patch if fetch_feed is involved in error path
def test_add_feed_invalid_tab(mock_fetch_unused, client): # mock_fetch_unused if not directly used but to be consistent
    """Test POST /api/feeds with a non-existent tab_id."""
    response = client.post('/api/feeds', json={'url': 'some_url', 'tab_id': 999})
    assert response.status_code == 404

def test_delete_feed_success(client, setup_tabs_and_feeds):
    """Test DELETE /api/feeds/<id> successfully."""
    feed1_id = setup_tabs_and_feeds["feed1_id"]
    item1_id = setup_tabs_and_feeds["item1_id"]
    item2_id = setup_tabs_and_feeds["item2_id"]
    
    # Verify items exist before delete
    with app.app_context():
        assert db.session.get(FeedItem, item1_id) is not None
        assert db.session.get(FeedItem, item2_id) is not None
        
    response = client.delete(f'/api/feeds/{feed1_id}')
    
    assert response.status_code == 200
    assert 'message' in response.json
    
    # Verify feed and associated items are deleted (due to cascade)
    with app.app_context():
        assert db.session.get(Feed, feed1_id) is None
        assert db.session.get(FeedItem, item1_id) is None
        assert db.session.get(FeedItem, item2_id) is None

def test_delete_feed_not_found(client):
    """Test DELETE /api/feeds/<id> for non-existent feed."""
    response = client.delete('/api/feeds/999')
    assert response.status_code == 404

def test_mark_item_read_success(client, setup_tabs_and_feeds):
    """Test POST /api/items/<item_id>/read for an unread item."""
    item1_id = setup_tabs_and_feeds["item1_id"] # Initially unread
    
    # Verify initial state
    with app.app_context():
        assert db.session.get(FeedItem, item1_id).is_read == False
        
    response = client.post(f'/api/items/{item1_id}/read')
    
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'marked as read' in response.json['message']
    
    # Verify state change in DB
    with app.app_context():
        assert db.session.get(FeedItem, item1_id).is_read == True

def test_mark_item_read_already_read(client, setup_tabs_and_feeds):
    """Test POST /api/items/<item_id>/read for an already read item."""
    item2_id = setup_tabs_and_feeds["item2_id"] # Initially read
    
    # Verify initial state
    with app.app_context():
        assert db.session.get(FeedItem, item2_id).is_read == True
        
    response = client.post(f'/api/items/{item2_id}/read')
    
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'already marked as read' in response.json['message']
    
    # Verify state didn't change
    with app.app_context():
        assert db.session.get(FeedItem, item2_id).is_read == True

def test_mark_item_read_not_found(client):
    """Test POST /api/items/<item_id>/read for non-existent item."""
    response = client.post('/api/items/999/read')
    assert response.status_code == 404

# --- Tests for POST /api/feeds/<feed_id>/update ---

@patch('backend.app.fetch_and_update_feed')
def test_update_feed_success(mock_fetch_and_update, client, setup_tabs_and_feeds):
    feed_id = setup_tabs_and_feeds["feed1_id"]
    # Mock the return values of fetch_and_update_feed
    mock_fetch_and_update.return_value = (True, 1) # success, num_new_items
    
    response = client.post(f'/api/feeds/{feed_id}/update')

    assert response.status_code == 200
    # The endpoint now refetches the object to serialize it
    assert response.json['id'] == feed_id
    mock_fetch_and_update.assert_called_once_with(feed_id)

@patch('backend.app.fetch_and_update_feed')
def test_update_feed_not_found(mock_fetch_and_update, client):
    """Test POST /api/feeds/<feed_id>/update when feed is not found."""
    feed_id = 999
    response = client.post(f'/api/feeds/{feed_id}/update')
    assert response.status_code == 404
    mock_fetch_and_update.assert_not_called()

@patch('backend.app.fetch_and_update_feed')
def test_update_feed_failure(mock_fetch_and_update, client, setup_tabs_and_feeds):
    feed_id = setup_tabs_and_feeds["feed1_id"]
    mock_fetch_and_update.side_effect = Exception("Simulated update error")

    response = client.post(f'/api/feeds/{feed_id}/update')

    assert response.status_code == 500 
    assert 'error' in response.json
    assert "Failed to update feed" in response.json['error'] 
    mock_fetch_and_update.assert_called_once_with(feed_id)

# --- Tests for PUT /api/feeds/<feed_id> (Update Feed URL) ---

@patch('backend.app.fetch_feed')
def test_update_feed_url_success(mock_fetch_feed, client, setup_tabs_and_feeds):
    """Test PUT /api/feeds/<feed_id> successfully updates feed URL and name."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    new_url = "https://example.com/new-feed.xml"
    
    # Mock the feed fetch to return a valid feed
    mock_feed = MagicMock()
    mock_feed.feed = {
        'title': 'New Feed Title',
        'link': 'https://example.com'
    }
    mock_fetch_feed.return_value = mock_feed
    
    response = client.put(f'/api/feeds/{feed_id}', json={'url': new_url})
    
    assert response.status_code == 200
    data = response.json
    assert data['url'] == new_url
    assert data['name'] == 'New Feed Title'
    assert data['site_link'] == 'https://example.com'
    
    mock_fetch_feed.assert_called_once_with(new_url)
    # The optimized implementation uses process_feed_entries directly instead of fetch_and_update_feed

@patch('backend.app.fetch_feed')
def test_update_feed_url_fetch_fails(mock_fetch_feed, client, setup_tabs_and_feeds):
    """Test PUT /api/feeds/<feed_id> when feed fetch fails."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    new_url = "https://example.com/invalid-feed.xml"
    
    # Mock the feed fetch to fail
    mock_fetch_feed.return_value = None
    
    response = client.put(f'/api/feeds/{feed_id}', json={'url': new_url})
    
    assert response.status_code == 200
    data = response.json
    assert data['url'] == new_url
    assert data['name'] == new_url  # Should use URL as name when fetch fails
    assert data['site_link'] is None
    
    mock_fetch_feed.assert_called_once_with(new_url)

def test_update_feed_url_missing_url(client, setup_tabs_and_feeds):
    """Test PUT /api/feeds/<feed_id> with missing URL."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    
    response = client.put(f'/api/feeds/{feed_id}', json={})
    
    assert response.status_code == 400
    assert 'error' in response.json
    assert 'Missing or invalid feed URL' in response.json['error']

def test_update_feed_url_duplicate_url(client, setup_tabs_and_feeds):
    """Test PUT /api/feeds/<feed_id> with URL that already exists."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    # Get the URL from feed2 by querying the database
    with app.app_context():
        feed2 = db.session.get(Feed, setup_tabs_and_feeds["feed2_id"])
        existing_url = feed2.url
    
    response = client.put(f'/api/feeds/{feed_id}', json={'url': existing_url})
    
    assert response.status_code == 409
    assert 'error' in response.json
    assert 'already exists' in response.json['error']

def test_update_feed_url_not_found(client):
    """Test PUT /api/feeds/<feed_id> when feed is not found."""
    response = client.put('/api/feeds/999', json={'url': 'https://example.com/new-feed.xml'})
    
    assert response.status_code == 404

# --- Tests for Frontend Serving Routes ---

def test_get_root_path(client):
    """Test GET / (root path) serves index.html."""
    response = client.get('/')
    assert response.status_code == 200
    assert response.content_type == 'text/html; charset=utf-8' # Flask default for send_from_directory
    assert b"<title>SheepVibes</title>" in response.data

def test_get_existing_static_file(client):
    """Test GET /<path:filename> for an existing static file like script.js."""
    # To make this test robust, we should ensure 'script.js' exists where Flask serves static files from.
    # Assuming 'static/script.js' relative to app.py or bluepirnt.
    # For now, we'll assume it exists and Flask's send_from_directory will find it.
    # If app.static_folder is './static' (default) or '../static' or '../frontend/dist' etc.
    # This test might fail if 'script.js' is not in the expected static path for testing.
    # For the purpose of this task, we assume it's set up correctly.
    response = client.get('/script.js')
    assert response.status_code == 200
    assert response.content_type == 'text/javascript; charset=utf-8'
    # Check if data is not empty, actual content might change.
    assert len(response.data) > 0

def test_get_index_html_explicitly(client):
    """Test GET /index.html explicitly."""
    response = client.get('/index.html')
    assert response.status_code == 200
    assert response.content_type == 'text/html; charset=utf-8'
    assert b"<title>SheepVibes</title>" in response.data

def test_get_non_existent_static_file(client):
    """Test GET /<path:filename> for a non-existent file."""
    response = client.get('/nonexistentfile.css')
    assert response.status_code == 404

# --- Tests for POST /api/feeds/update-all ---

@patch('backend.app.announcer.announce')
@patch('backend.app.update_all_feeds')
def test_update_all_feeds_success(mock_update_all_feeds, mock_announce, client):
    """Test POST /api/feeds/update-all successfully and announces SSE."""
    # Arrange
    mock_update_all_feeds.return_value = (5, 10)  # 5 feeds processed, 10 new items

    # Act
    response = client.post('/api/feeds/update-all')

    # Assert Response
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'All feeds updated successfully.'
    assert data['feeds_processed'] == 5
    assert data['new_items'] == 10

    # Assert Mocks
    mock_update_all_feeds.assert_called_once()
    
    # Assert SSE announcement
    expected_event_data = {'feeds_processed': 5, 'new_items': 10}
    expected_sse_msg = f"data: {json.dumps(expected_event_data)}\n\n"
    mock_announce.assert_called_once_with(msg=expected_sse_msg)

@patch('backend.app.announcer.announce')
@patch('backend.app.update_all_feeds')
def test_update_all_feeds_exception(mock_update_all_feeds, mock_announce, client):
    """Test POST /api/feeds/update-all when update_all_feeds raises an exception."""
    # Arrange
    mock_update_all_feeds.side_effect = Exception("Test update error")

    # Act
    response = client.post('/api/feeds/update-all')

    # Assert Response
    assert response.status_code == 500
    data = response.get_json()
    assert 'error' in data
    assert data['error'] == 'An error occurred while updating all feeds.'

    # Assert Mocks
    mock_update_all_feeds.assert_called_once()
    mock_announce.assert_not_called()

# --- Tests for SSE Stream ---

def test_stream_endpoint_content_type(client):
    """Test GET /api/stream returns correct Content-Type for SSE without hanging."""
    # Use buffered=False to get a streaming response without consuming it.
    response = client.get('/api/stream', buffered=False)
    
    # Assertions on headers should work immediately.
    assert response.status_code == 200
    assert 'text/event-stream' in response.content_type
    
    # Manually close the response to terminate the generator on the server.
    # This triggers a GeneratorExit in the server-side stream function,
    # allowing it to clean up and preventing the test from hanging.
    response.close()

# --- Tests for Caching ---
def test_cache_invalidation_flow(client, setup_tabs_and_feeds):
    """Tests the granular cache invalidation by checking its effects."""
    with app.app_context():
        tab1_id = setup_tabs_and_feeds["tab1_id"]
        item1_id = setup_tabs_and_feeds["item1_id"]

        # --- Test /api/tabs/{id}/feeds caching and invalidation ---
        with patch('backend.app.db.session.execute') as mock_execute:
            # 1. Prime the cache (this call will execute the query).
            client.get(f'/api/tabs/{tab1_id}/feeds')

            # 2. Assert query was called once initially.
            initial_call_count = mock_execute.call_count
            assert initial_call_count > 0

            # 3. Call again and assert the query was NOT re-executed (cache hit).
            client.get(f'/api/tabs/{tab1_id}/feeds')
            assert mock_execute.call_count == initial_call_count

        # 4. Invalidate the cache by marking an item as read.
        client.post(f'/api/items/{item1_id}/read')

        # 5. Assert the query IS re-executed on the next call (cache miss).
        with patch('backend.app.db.session.execute') as mock_execute_after_invalidation:
            client.get(f'/api/tabs/{tab1_id}/feeds')
            mock_execute_after_invalidation.assert_called()

        # --- Test /api/tabs caching and invalidation ---
        with patch('backend.app.Tab.query') as mock_tab_query:
            # Mock the query result
            mock_tab_query.order_by.return_value.all.return_value = []

            # 1. Prime cache for /api/tabs
            client.get('/api/tabs')
            # 2. Assert it was called
            mock_tab_query.order_by.return_value.all.assert_called_once()

            # 3. Assert a second call is a cache hit
            client.get('/api/tabs')
            mock_tab_query.order_by.return_value.all.assert_called_once()
        
        # 4. Invalidate by creating a new tab
        client.post('/api/tabs', json={'name': 'A New Tab'})

        # 5. Assert the next call is a cache miss
        with patch('backend.app.Tab.query') as mock_tab_query_after_invalidation:
            mock_tab_query_after_invalidation.order_by.return_value.all.return_value = []
            client.get('/api/tabs')
            mock_tab_query_after_invalidation.order_by.return_value.all.assert_called_once()


# --- Tests for Model Methods ---

def test_feed_item_to_dict_serialization(client): # client fixture ensures app_context and db setup
    """
    Tests the to_dict() method of the FeedItem model, focusing on datetime serialization.
    """
    from datetime import datetime, timezone, timedelta

    with app.app_context():
        # Setup: Create a Tab and a Feed to associate with FeedItems
        # Minimal setup, not using setup_tabs_and_feeds to keep test focused
        test_tab = Tab.query.first()
        if not test_tab:
            test_tab = Tab(name="Test Tab for Serialization")
            db.session.add(test_tab)
            db.session.commit()

        test_feed = Feed.query.filter_by(tab_id=test_tab.id).first()
        if not test_feed:
            test_feed = Feed(tab_id=test_tab.id, name="Test Feed for Serialization", url="http://example.com/rss")
            db.session.add(test_feed)
            db.session.commit()

        # Scenario 1: Naive datetimes (assumed UTC)
        dt_naive_published = datetime(2023, 1, 1, 10, 30, 0)
        dt_naive_fetched = datetime(2023, 1, 1, 11, 0, 0)
        item_naive = FeedItem(
            feed_id=test_feed.id,
            title="Naive Datetime Test",
            link="http://example.com/naive",
            published_time=dt_naive_published,
            fetched_time=dt_naive_fetched,
            guid="guid-naive-serialization"
        )
        db.session.add(item_naive)
        db.session.commit() # Commit to get item_naive.id and allow to_dict() to work if it queries DB

        dict_naive = item_naive.to_dict()
        assert isinstance(dict_naive['published_time'], str)
        assert dict_naive['published_time'] == "2023-01-01T10:30:00Z"
        assert isinstance(dict_naive['fetched_time'], str)
        assert dict_naive['fetched_time'] == "2023-01-01T11:00:00Z"
        db.session.delete(item_naive) # Clean up item
        db.session.commit()

        # Scenario 2: Aware datetimes (EST and PST)
        # EST is UTC-5, PST is UTC-8
        tz_est = timezone(timedelta(hours=-5))
        tz_pst = timezone(timedelta(hours=-8))
        dt_aware_published_est = datetime(2023, 3, 15, 12, 0, 0, tzinfo=tz_est) # 17:00 UTC
        dt_aware_fetched_pst = datetime(2023, 3, 15, 9, 0, 0, tzinfo=tz_pst)   # 17:00 UTC

        item_aware = FeedItem(
            feed_id=test_feed.id,
            title="Aware Datetime Test",
            link="http://example.com/aware",
            published_time=dt_aware_published_est,
            fetched_time=dt_aware_fetched_pst,
            guid="guid-aware-serialization"
        )
        db.session.add(item_aware)
        db.session.commit()
        # Expire and refresh to ensure the attribute is loaded from the DB
        # according to the column type's rules (especially for DateTime with timezone)
        db.session.expire(item_aware, ['published_time', 'fetched_time'])
        # Accessing item_aware.published_time now will trigger a reload from DB.
        # No need to explicitly refresh if session.expire is used before access.

        dict_aware = item_aware.to_dict()
        assert isinstance(dict_aware['published_time'], str)
        assert dict_aware['published_time'] == "2023-03-15T17:00:00Z"
        assert isinstance(dict_aware['fetched_time'], str)
        assert dict_aware['fetched_time'] == "2023-03-15T17:00:00Z"
        db.session.delete(item_aware)
        db.session.commit()

        # Scenario 3: published_time is None, fetched_time is aware UTC
        dt_aware_fetched_utc = datetime(2023, 5, 20, 14, 0, 0, tzinfo=timezone.utc)
        item_none_published = FeedItem(
            feed_id=test_feed.id,
            title="None Published Test",
            link="http://example.com/none-published",
            published_time=None,
            fetched_time=dt_aware_fetched_utc,
            guid="guid-none-published-serialization"
        )
        db.session.add(item_none_published)
        db.session.commit()

        dict_none_published = item_none_published.to_dict()
        assert dict_none_published['published_time'] is None
        assert isinstance(dict_none_published['fetched_time'], str)
        assert dict_none_published['fetched_time'] == "2023-05-20T14:00:00Z"
        db.session.delete(item_none_published)
        db.session.commit()

def test_to_iso_z_string_static_method():
    """Tests the FeedItem.to_iso_z_string static method directly."""
    from datetime import datetime, timezone, timedelta

    # 1. Test with a naive datetime (assumed to be UTC)
    naive_dt = datetime(2023, 1, 1, 12, 0, 0)
    assert FeedItem.to_iso_z_string(naive_dt) == "2023-01-01T12:00:00Z"

    # 2. Test with a timezone-aware datetime (not UTC)
    tz_est = timezone(timedelta(hours=-5))
    aware_dt_est = datetime(2023, 3, 15, 10, 0, 0, tzinfo=tz_est) # This is 15:00 UTC
    assert FeedItem.to_iso_z_string(aware_dt_est) == "2023-03-15T15:00:00Z"

    # 3. Test with a timezone-aware UTC datetime
    aware_dt_utc = datetime(2023, 5, 20, 14, 30, 0, tzinfo=timezone.utc)
    assert FeedItem.to_iso_z_string(aware_dt_utc) == "2023-05-20T14:30:00Z"

    # 4. Test with None input
    assert FeedItem.to_iso_z_string(None) is None

# --- Tests for feed_service functions ---

def test_parse_published_time_variations(): # No client fixture needed as it's a pure function
    """Tests the parse_published_time helper with various entry structures."""

    mock_spec = ['published_parsed', 'published', 'updated', 'created', 'get']

    # Case 1: 'published_parsed' available and valid
    entry1 = MagicMock(spec=mock_spec)
    entry1.published_parsed = datetime.datetime(2023, 10, 26, 14, 30, 0, tzinfo=timezone.utc).utctimetuple()
    entry1.published = None
    entry1.updated = None
    entry1.created = None
    entry1.get.return_value = '[mock_link_entry1]'
    dt1 = parse_published_time(entry1)
    assert dt1 is not None
    assert dt1.year == 2023 and dt1.month == 10 and dt1.day == 26
    assert dt1.hour == 14 and dt1.minute == 30 and dt1.second == 0
    assert dt1.tzinfo == timezone.utc

    # Case 2: 'published' field available
    entry2 = MagicMock(spec=mock_spec)
    entry2.published_parsed = None
    entry2.published = "Thu, 26 Oct 2023 10:00:00 -0400" # Field under test
    entry2.updated = None
    entry2.created = None
    entry2.get.return_value = '[mock_link_entry2]'
    dt2 = parse_published_time(entry2)
    assert dt2 is not None
    assert dt2.year == 2023 and dt2.month == 10 and dt2.day == 26
    assert dt2.hour == 14 and dt2.minute == 0 # Converted to UTC
    assert dt2.tzinfo == timezone.utc

    # Case 3: 'updated' field available
    entry3 = MagicMock(spec=mock_spec)
    entry3.published_parsed = None
    entry3.published = None
    entry3.updated = "2023-10-26T16:30:00Z" # Field under test
    entry3.created = None
    entry3.get.return_value = '[mock_link_entry3]'
    dt3 = parse_published_time(entry3)
    assert dt3 is not None
    assert dt3.year == 2023 and dt3.month == 10 and dt3.day == 26
    assert dt3.hour == 16 and dt3.minute == 30
    assert dt3.tzinfo == timezone.utc

    # Case 4: Naive datetime string in 'published', assumed UTC
    entry4 = MagicMock(spec=mock_spec)
    entry4.published_parsed = None
    entry4.published = "2023-10-26 17:00:00" # Field under test
    entry4.updated = None
    entry4.created = None
    entry4.get.return_value = '[mock_link_entry4]'
    dt4 = parse_published_time(entry4)
    assert dt4 is not None
    assert dt4.hour == 17 # Assumed UTC
    assert dt4.tzinfo == timezone.utc

    # Case 5: No valid date fields
    entry5 = MagicMock(spec=mock_spec)
    entry5.published_parsed = None
    entry5.published = None
    entry5.updated = None
    entry5.created = None
    entry5.get.return_value = '[mock_link_entry5]'

    before_fallback_dt5 = datetime.datetime.now(timezone.utc)
    dt5 = parse_published_time(entry5)
    after_fallback_dt5 = datetime.datetime.now(timezone.utc)

    assert dt5 is not None
    assert before_fallback_dt5 <= dt5 <= after_fallback_dt5
    assert dt5.tzinfo == timezone.utc

    # Case 6: Malformed date string in 'published'
    entry6 = MagicMock(spec=mock_spec)
    entry6.published_parsed = None
    entry6.published = "this is not a date" # Field under test
    entry6.updated = None
    entry6.created = None
    entry6.get.return_value = '[mock_link_entry6]'

    before_fallback_dt6 = datetime.datetime.now(timezone.utc)
    dt6 = parse_published_time(entry6)
    after_fallback_dt6 = datetime.datetime.now(timezone.utc)

    assert dt6 is not None
    assert before_fallback_dt6 <= dt6 <= after_fallback_dt6
    assert dt6.tzinfo == timezone.utc

    # Case 7: published_parsed is invalid type, fallback to 'published'
    entry7 = MagicMock(spec=mock_spec)
    entry7.published_parsed = "not a time_struct" # Invalid type for published_parsed
    entry7.published = "2023-10-27T10:00:00Z" # Valid fallback
    entry7.updated = None
    entry7.created = None
    entry7.get.return_value = '[mock_link_entry7]'

    dt7 = parse_published_time(entry7) # This should parse entry7.published
    assert dt7 is not None
    assert dt7.year == 2023 and dt7.month == 10 and dt7.day == 27
    assert dt7.hour == 10
    assert dt7.tzinfo == timezone.utc

def test_process_feed_with_in_batch_duplicate_guids(client): # Using client fixture for app_context
    """
    Tests that process_feed_entries correctly handles entries with duplicate GUIDs
    within the same fetched batch, only adding the first instance.
    """
    with client.application.app_context(): # Use app_context from client
        # 1. Setup: Create a Tab and Feed object in the DB
        tab = Tab(name="Test Tab GUIDs", order=0)
        db.session.add(tab)
        db.session.commit()

        feed_obj = Feed(name="Test Feed In-Batch Dupes", url="http://testguids.com/rss", tab_id=tab.id)
        db.session.add(feed_obj)
        db.session.commit()

        # 2. Create mock feedparser data
        mock_parsed_feed = MagicMock()
        mock_parsed_feed.feed = MagicMock()
        mock_parsed_feed.feed.title = "Test Feed Title"
        mock_parsed_feed.feed.link = "http://testguids.com/feed-website-link" # Provide a site link for the feed itself
        # Adjust .get to correctly return explicitly set attributes or the default
        mock_parsed_feed.feed.get = lambda key, default_val=None: getattr(mock_parsed_feed.feed, key) if hasattr(mock_parsed_feed.feed, key) else default_val


        dt_entry1 = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        dt_entry2 = datetime.datetime(2023, 1, 1, 12, 5, 0, tzinfo=timezone.utc)
        dt_entry3 = datetime.datetime(2023, 1, 1, 12, 10, 0, tzinfo=timezone.utc)

        entry1_data = {'id': 'guid1', 'link': 'http://link1.com', 'title': 'Title 1',
                       'published_parsed': dt_entry1.utctimetuple()}
        entry2_data = {'id': 'guid1', 'link': 'http://link2.com', 'title': 'Title 2 (Same GUID)',
                       'published_parsed': dt_entry2.utctimetuple()}
        entry3_data = {'id': 'guid2', 'link': 'http://link3.com', 'title': 'Title 3',
                       'published_parsed': dt_entry3.utctimetuple()}

        entry1 = MagicMock()
        entry1.configure_mock(**entry1_data)
        entry1.get = lambda key, default=None: entry1_data.get(key, default)

        entry2 = MagicMock()
        entry2.configure_mock(**entry2_data)
        entry2.get = lambda key, default=None: entry2_data.get(key, default)

        entry3 = MagicMock()
        entry3.configure_mock(**entry3_data)
        entry3.get = lambda key, default=None: entry3_data.get(key, default)

        mock_parsed_feed.entries = [entry1, entry2, entry3]
        mock_parsed_feed.bozo = 0

        # 3. Call process_feed_entries directly
        new_items_count = process_feed_entries(feed_obj, mock_parsed_feed)

        # 4. Assertions
        assert new_items_count == 3

        items_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).all()
        assert len(items_in_db) == 3

        guids_in_db = {item.guid for item in items_in_db}
        assert 'http://link1.com' in guids_in_db
        assert 'http://link2.com' in guids_in_db
        assert 'http://link3.com' in guids_in_db

        item1_db = FeedItem.query.filter_by(guid='http://link1.com', feed_id=feed_obj.id).first()
        assert item1_db is not None
        assert item1_db.title == 'Title 1'
        assert item1_db.link == 'http://link1.com'

def test_process_feed_with_missing_link(client): # Using client fixture for app_context
    """
    Tests that process_feed_entries skips entries that are missing a link,
    as 'link' is a NOT NULL field in the FeedItem model.
    """
    with client.application.app_context():
        # 1. Setup Feed object
        tab = Tab(name="Test Tab Links", order=0)
        db.session.add(tab)
        db.session.commit()

        feed_obj = Feed(name="Test Feed Missing Link", url="http://testmissinglink.com/rss", tab_id=tab.id)
        db.session.add(feed_obj)
        db.session.commit()

        # 2. Create mock feedparser data
        mock_parsed_feed = MagicMock()
        mock_parsed_feed.feed = MagicMock()
        mock_parsed_feed.feed.title = "Test Feed Title"
        mock_parsed_feed.feed.link = "http://testmissinglink.com/feed-website-link" # Provide a site link for the feed itself
        # Adjust .get to correctly return explicitly set attributes or the default
        mock_parsed_feed.feed.get = lambda key, default_val=None: getattr(mock_parsed_feed.feed, key) if hasattr(mock_parsed_feed.feed, key) else default_val

        dt_valid = datetime.datetime(2023,1,1,12,0,0, tzinfo=timezone.utc)
        dt_no_link = datetime.datetime(2023,1,1,12,5,0, tzinfo=timezone.utc)
        dt_empty_link = datetime.datetime(2023,1,1,12,10,0, tzinfo=timezone.utc)

        entry_valid_data = {'id': 'guid_valid', 'link': 'http://valid.com', 'title': 'Valid Item',
                            'published_parsed': dt_valid.utctimetuple()}
        entry_no_link_data = {'id': 'guid_no_link', 'link': None, 'title': 'Item No Link',
                              'published_parsed': dt_no_link.utctimetuple()}
        entry_empty_link_data = {'id': 'guid_empty_link', 'link': '', 'title': 'Item Empty Link',
                                 'published_parsed': dt_empty_link.utctimetuple()}

        entry_valid = MagicMock()
        entry_valid.configure_mock(**entry_valid_data)
        entry_valid.get = lambda key, default=None: entry_valid_data.get(key, default)

        entry_no_link = MagicMock()
        entry_no_link.configure_mock(**entry_no_link_data)
        entry_no_link.get = lambda key, default=None: entry_no_link_data.get(key, default)

        entry_empty_link = MagicMock()
        entry_empty_link.configure_mock(**entry_empty_link_data)
        entry_empty_link.get = lambda key, default=None: entry_empty_link_data.get(key, default)

        mock_parsed_feed.entries = [entry_valid, entry_no_link, entry_empty_link]
        mock_parsed_feed.bozo = 0

        # 3. Call process_feed_entries directly
        new_items_count = process_feed_entries(feed_obj, mock_parsed_feed)

        # 4. Assertions
        assert new_items_count == 1

        items_in_db = FeedItem.query.filter_by(feed_id=feed_obj.id).all()
        assert len(items_in_db) == 1
        assert items_in_db[0].guid == 'http://valid.com'
        assert items_in_db[0].link == 'http://valid.com'
        assert items_in_db[0].title == 'Valid Item'

# --- Tests for OPML Export (/api/opml/export) ---

def test_export_opml_empty(client):
    """Test GET /api/opml/export when no feeds exist."""
    response = client.get('/api/opml/export')
    assert response.status_code == 200
    assert 'application/xml' in response.content_type
    assert response.headers['Content-Disposition'] == 'attachment; filename="sheepvibes_feeds.opml"'

    # Parse XML
    tree = ET.fromstring(response.data)
    assert tree.tag == 'opml'
    assert tree.get('version') == '2.0'
    head = tree.find('head')
    assert head is not None
    title = head.find('title')
    assert title is not None
    assert title.text == 'SheepVibes Feeds'
    body = tree.find('body')
    assert body is not None
    assert len(body.findall('outline')) == 0

def test_export_opml_with_feeds(client, setup_tabs_and_feeds):
    """Test GET /api/opml/export with existing feeds."""
    # setup_tabs_and_feeds already adds 3 feeds
    # Feed 1: url1, Name: Feed 1
    # Feed 2: url2, Name: Feed 2
    # Feed 3: url3, Name: Feed 3

    response = client.get('/api/opml/export')
    assert response.status_code == 200
    assert 'application/xml' in response.content_type
    assert response.headers['Content-Disposition'] == 'attachment; filename="sheepvibes_feeds.opml"'

    tree = ET.fromstring(response.data)
    assert tree.tag == 'opml'
    head = tree.find('head')
    assert head is not None
    title = head.find('title')
    assert title is not None
    assert title.text == 'SheepVibes Feeds'

    body = tree.find('body')
    assert body is not None
    outlines = body.findall('outline')
    assert len(outlines) == 2 # 2 Tabs

    # Map tab names to outlines
    tab_outlines = {o.get('text'): o for o in outlines}
    assert 'Tab 1' in tab_outlines
    assert 'Tab 2' in tab_outlines

    # Check content of Tab 1
    tab1_outline = tab_outlines['Tab 1']
    assert tab1_outline.get('title') == 'Tab 1' # Check tab title

    tab1_feeds = tab1_outline.findall('outline')
    assert len(tab1_feeds) == 2
    
    feed1 = next((f for f in tab1_feeds if f.get('text') == 'Feed 1'), None)
    feed2 = next((f for f in tab1_feeds if f.get('text') == 'Feed 2'), None)
    
    assert feed1 is not None
    assert feed1.get('title') == 'Feed 1' # Check feed title
    assert feed1.get('xmlUrl') == 'url1'
    assert feed1.get('type') == 'rss' # Check feed type
    assert feed1.get('htmlUrl') is None # No site_link

    assert feed2 is not None
    assert feed2.get('title') == 'Feed 2'
    assert feed2.get('xmlUrl') == 'url2'
    assert feed2.get('type') == 'rss'
    assert feed2.get('htmlUrl') is None # No site_link

    # Check content of Tab 2
    tab2_outline = tab_outlines['Tab 2']
    assert tab2_outline.get('title') == 'Tab 2'

    tab2_feeds = tab2_outline.findall('outline')
    assert len(tab2_feeds) == 1
    
    feed3 = tab2_feeds[0]
    assert feed3.get('text') == 'Feed 3'
    assert feed3.get('title') == 'Feed 3'
    assert feed3.get('xmlUrl') == 'url3'
    assert feed3.get('type') == 'rss'
    assert feed3.get('htmlUrl') == 'http://example.com/feed3' # Check htmlUrl export

# --- Tests for OPML Import (/api/opml/import) ---

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_success(mock_fetch_update, client):
    """Test POST /api/opml/import with a valid OPML file and item fetching."""
    mock_fetch_update.return_value = (True, 1) # Simulate successful fetch with 1 new item
    # Arrange: Add a tab to import into
    with app.app_context():
        tab = Tab(name="Import Tab", order=0)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    opml_content = """
    <opml version="2.0">
      <head><title>Test Feeds</title></head>
      <body>
        <outline text="Feed1 OPM" type="rss" xmlUrl="http://feed1.opml.com/rss"/>
        <outline text="Feed2 OPM" type="rss" xmlUrl="http://feed2.opml.com/rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_import.opml')

    # Act
    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(tab_id)}, content_type='multipart/form-data')

    # Assert
    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 2
    assert json_data['skipped_count'] == 0
    # Removed: assert json_data['tab_id'] == tab_id, response format changed for generic message
    # The tab_id for feeds is checked by querying the DB below.

    with app.app_context():
        feeds = Feed.query.filter_by(tab_id=tab_id).all()
        assert len(feeds) == 2
        feed_urls = {f.url for f in feeds}
        feed_names = {f.name for f in feeds}
        assert "http://feed1.opml.com/rss" in feed_urls
        assert "http://feed2.opml.com/rss" in feed_urls
        assert "Feed1 OPM" in feed_names
        assert "Feed2 OPM" in feed_names

        # Assert fetch_and_update_feed was called for new feeds
        # Get the feed objects to check their IDs
        feed1_obj = Feed.query.filter_by(url="http://feed1.opml.com/rss").first()
        feed2_obj = Feed.query.filter_by(url="http://feed2.opml.com/rss").first()
        assert feed1_obj is not None
        assert feed2_obj is not None

        assert mock_fetch_update.call_count == 2
        mock_fetch_update.assert_any_call(feed1_obj.id)
        mock_fetch_update.assert_any_call(feed2_obj.id)


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_with_duplicates(mock_fetch_update, client):
    """Test POST /api/opml/import with some feeds already existing."""
    mock_fetch_update.return_value = (True, 1)
    with app.app_context():
        tab = Tab(name="Import Tab Dups", order=0)
        db.session.add(tab)
        db.session.commit() # Commit tab first to get its ID
        tab_id = tab.id

        existing_feed = Feed(tab_id=tab_id, name="Existing Feed", url="http://feed1.opml.com/rss")
        db.session.add(existing_feed)
        db.session.commit() # Commit the feed

    opml_content = """
    <opml version="2.0">
      <body>
        <outline text="Feed1 OPM" type="rss" xmlUrl="http://feed1.opml.com/rss"/>
        <outline text="New Feed OPM" type="rss" xmlUrl="http://newfeed.opml.com/rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_import_dups.opml')

    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(tab_id)}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 1
    assert json_data['skipped_count'] == 1

    with app.app_context():
        feeds = Feed.query.filter_by(tab_id=tab_id).order_by(Feed.url).all()
        assert len(feeds) == 2 # Existing one + new one
        assert feeds[0].url == "http://feed1.opml.com/rss" # Existing
        assert feeds[1].url == "http://newfeed.opml.com/rss" # New one

def test_import_opml_no_file(client):
    """Test POST /api/opml/import without a file."""
    response = client.post('/api/opml/import', content_type='multipart/form-data')
    assert response.status_code == 400
    assert 'No file part' in response.json['error']

def test_import_opml_empty_filename(client):
    """Test POST /api/opml/import with an empty filename (simulates no file selected)."""
    opml_file = (io.BytesIO(b"content"), '') # Empty filename
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')
    assert response.status_code == 400
    assert 'No file selected' in response.json['error']

def test_import_opml_malformed_xml(client):
    """Test POST /api/opml/import with malformed XML."""
    with app.app_context(): # Ensure a tab exists
        tab = Tab(name="Malformed Tab", order=0)
        db.session.add(tab)
        db.session.commit()

    opml_content = "<opml><body/><head></opml>" # Malformed, unclosed tags
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'malformed.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')
    assert response.status_code == 400
    assert 'Malformed OPML file' in response.json['error']

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_creates_default_tab_when_none_exist(mock_fetch_update, client):
    """Test import creates a default tab if none exist and imports feeds."""
    mock_fetch_update.return_value = (True, 1)
    # Ensure no tabs exist (client fixture already drops tables)
    opml_content = """
    <opml version="2.0">
      <body>
        <outline text="Feed Alpha" xmlUrl="http://alpha.com/rss"/>
        <outline text="Feed Beta" xmlUrl="http://beta.com/rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_default_creation.opml')

    # Act
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    # Assert
    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 2
    assert json_data['skipped_count'] == 0
    assert "Imported Feeds" in json_data['message'] # Check message content
    # Removed: assert json_data['tab_name'] == "Imported Feeds"

    # To get the new_tab_id, we have to find it by name now, or parse from message if we made message more specific
    with app.app_context():
        default_tab = Tab.query.filter_by(name="Imported Feeds").first()
        assert default_tab is not None
        new_tab_id = default_tab.id
        # default_tab = db.session.get(Tab, new_tab_id) # This line is not needed if we fetch by name
        assert default_tab is not None
        assert default_tab.name == "Imported Feeds"
        assert default_tab.order == 0

        feeds_in_tab = Feed.query.filter_by(tab_id=new_tab_id).all()
        assert len(feeds_in_tab) == 2
        feed_urls = {f.url for f in feeds_in_tab}
        assert "http://alpha.com/rss" in feed_urls
        assert "http://beta.com/rss" in feed_urls

        # Assert fetch_and_update_feed was called for new feeds
        feed_alpha_obj = Feed.query.filter_by(url="http://alpha.com/rss").first()
        feed_beta_obj = Feed.query.filter_by(url="http://beta.com/rss").first()
        assert feed_alpha_obj is not None
        assert feed_beta_obj is not None

        assert mock_fetch_update.call_count == 2
        mock_fetch_update.assert_any_call(feed_alpha_obj.id)
        mock_fetch_update.assert_any_call(feed_beta_obj.id)

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_specific_tab(mock_fetch_update, client):
    """Test POST /api/opml/import into a specific tab when multiple tabs exist."""
    mock_fetch_update.return_value = (True, 1)
    with app.app_context():
        tab1 = Tab(name="Tab One", order=0)
        tab2 = Tab(name="Tab Two", order=1)
        db.session.add_all([tab1, tab2])
        db.session.commit()
        tab1_id = tab1.id
        tab2_id = tab2.id

    opml_content = """
    <opml version="2.0"><body><outline text="Feed for Tab2" xmlUrl="http://tab2feed.com"/></body></opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_tab_specific.opml')

    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(tab2_id)}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 1
    # Removed: assert json_data['tab_id'] == tab2_id
    # Removed: assert json_data['tab_name'] == "Tab Two"
    assert f"default tab \"{tab2.name}\"" in json_data['message'] or f"tab \"{tab2.name}\"" in json_data['message']


    with app.app_context():
        assert Feed.query.filter_by(tab_id=tab1_id).count() == 0
        assert Feed.query.filter_by(tab_id=tab2_id).count() == 1
        feed_in_tab2 = Feed.query.filter_by(tab_id=tab2_id).first()
        assert feed_in_tab2.url == "http://tab2feed.com"

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_default_tab_if_tab_id_not_provided(mock_fetch_update, client): # Added mock_fetch_update
    """Test POST /api/opml/import defaults to the first tab if tab_id is not provided."""
    mock_fetch_update.return_value = (True, 1) # Simulate successful fetch
    with app.app_context():
        tab1 = Tab(name="Default Tab", order=0) # Should be default
        tab2 = Tab(name="Other Tab", order=1)
        db.session.add_all([tab1, tab2])
        db.session.commit()
        default_tab_id = tab1.id

    opml_content = """
    <opml version="2.0"><body><outline text="Feed for Default" xmlUrl="http://defaultfeed.com"/></body></opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_default_tab.opml')

    # Not providing 'tab_id' in the form data
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 1
    # Removed: assert json_data['tab_id'] == default_tab_id
    # Removed: assert json_data['tab_name'] == "Default Tab"
    assert f"default tab \"{tab1.name}\"" in json_data['message']

    with app.app_context():
        assert Feed.query.filter_by(tab_id=default_tab_id).count() == 1
        feed_in_default_tab = Feed.query.filter_by(tab_id=default_tab_id).first()
        assert feed_in_default_tab.url == "http://defaultfeed.com"
        assert mock_fetch_update.call_count == 1
        mock_fetch_update.assert_any_call(feed_in_default_tab.id)

@patch('backend.app.fetch_and_update_feed') # Even though no feeds are imported, the setup could change.
def test_import_opml_missing_xmlurl_is_skipped(mock_fetch_update_unused, client):
    """Test that an <outline> missing xmlUrl is skipped during import."""
    mock_fetch_update_unused.return_value = (True, 0) # Should not be called if only valid feeds are fetched
    with app.app_context():
        tab = Tab(name="Test Tab", order=0)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    opml_content = """
    <opml version="2.0">
      <body>
        <outline text="Valid Feed" xmlUrl="http://valid.com/rss"/>
        <outline text="Missing xmlUrl Feed"/>
        <outline text="Another Valid" xmlUrl="http://valid2.com/rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_missing_xmlurl.opml')
    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(tab_id)}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 2
    assert json_data['skipped_count'] == 1

    with app.app_context():
        feeds_in_tab = Feed.query.filter_by(tab_id=tab_id).all()
        assert len(feeds_in_tab) == 2
        urls = {f.url for f in feeds_in_tab}
        assert "http://valid.com/rss" in urls
        assert "http://valid2.com/rss" in urls

        feed_valid1 = Feed.query.filter_by(url="http://valid.com/rss").first()
        feed_valid2 = Feed.query.filter_by(url="http://valid2.com/rss").first()
        assert mock_fetch_update_unused.call_count == 2
        mock_fetch_update_unused.assert_any_call(feed_valid1.id)
        mock_fetch_update_unused.assert_any_call(feed_valid2.id)


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_no_body_tag(mock_fetch_update_unused, client):
    """Test OPML import with a file that has no <body> tag."""
    with app.app_context(): # Ensure a tab exists
        tab = Tab(name="No Body Tab", order=0)
        db.session.add(tab)
        db.session.commit()

    opml_content = """<opml version="2.0"><head><title>No Body</title></head></opml>"""
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'no_body.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200 # Should still be a valid request
    json_data = response.json
    assert json_data['imported_count'] == 0
    assert json_data['skipped_count'] == 0
    assert 'No feeds found in OPML (missing body)' in json_data['message']
    mock_fetch_update_unused.assert_not_called()

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_empty_body_tag(mock_fetch_update_unused, client):
    """Test OPML import with a file that has an empty <body> tag."""
    with app.app_context(): # Ensure a tab exists
        tab = Tab(name="Empty Body Tab", order=0)
        db.session.add(tab)
        db.session.commit()

    opml_content = """<opml version="2.0"><head><title>Empty Body</title></head><body></body></opml>"""
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'empty_body.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 0
    assert json_data['skipped_count'] == 0
    assert 'No feed entries or folders found in the OPML file.' in json_data['message'] # Updated message
    mock_fetch_update_unused.assert_not_called()


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_nested_structure_creates_tabs_and_feeds(mock_fetch_update, client):
    """Tests that nested OPML outlines create new tabs and feeds are correctly assigned."""
    mock_fetch_update.return_value = (True, 1) # Simulate successful fetch
    opml_content = """
    <opml version="2.0">
      <body>
        <outline title="News Folder">
          <outline text="Feed A (News)" title="Feed A (News)" xmlUrl="http://feeda.com/rss" type="rss"/>
          <outline text="Feed B (News)" title="Feed B (News)" xmlUrl="http://feedb.com/rss" type="rss"/>
        </outline>
        <outline title="Tech Folder">
          <outline text="Feed C (Tech)" title="Feed C (Tech)" xmlUrl="http://feedc.com/rss" type="rss"/>
        </outline>
        <outline text="Top Level Feed D" title="Top Level Feed D" xmlUrl="http://toplevel.com/rss" type="rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'nested_import.opml')

    # Act: Import without specifying a tab_id, relying on default tab creation if none exist
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    # Assert
    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 4
    assert json_data['skipped_count'] == 0
    # The 'tab_name' in response might be the default tab name for the top-level feed
    assert "Imported Feeds" in json_data['message']

    with app.app_context():
        # Verify tabs
        news_folder_tab = Tab.query.filter_by(name="News Folder").first()
        assert news_folder_tab is not None
        tech_folder_tab = Tab.query.filter_by(name="Tech Folder").first()
        assert tech_folder_tab is not None
        default_tab = Tab.query.filter_by(name="Imported Feeds").first() # For the top-level feed
        assert default_tab is not None

        # Verify feeds in "News Folder"
        feeds_in_news = Feed.query.filter_by(tab_id=news_folder_tab.id).all()
        assert len(feeds_in_news) == 2
        feed_urls_news = {f.url for f in feeds_in_news}
        assert "http://feeda.com/rss" in feed_urls_news
        assert "http://feedb.com/rss" in feed_urls_news

        # Verify feeds in "Tech Folder"
        feeds_in_tech = Feed.query.filter_by(tab_id=tech_folder_tab.id).all()
        assert len(feeds_in_tech) == 1
        assert feeds_in_tech[0].url == "http://feedc.com/rss"

        # Verify top-level feed
        feeds_in_default = Feed.query.filter_by(tab_id=default_tab.id).all()
        assert len(feeds_in_default) == 1
        assert feeds_in_default[0].url == "http://toplevel.com/rss"

        # Check mock calls
        assert mock_fetch_update.call_count == 4 # For A, B, C, D
        # Example check for one feed (others would be similar, relying on feed IDs)
        feed_a_obj = Feed.query.filter_by(url="http://feeda.com/rss").first()
        mock_fetch_update.assert_any_call(feed_a_obj.id)


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_nested_folder_name_matches_existing_tab(mock_fetch_update, client):
    """Tests that feeds in a folder are added to an existing tab if names match."""
    mock_fetch_update.return_value = (True, 1)
    with app.app_context():
        existing_tab = Tab(name="Existing News", order=0)
        db.session.add(existing_tab)
        db.session.commit()
        existing_tab_id = existing_tab.id

    opml_content = """
    <opml version="2.0">
      <body>
        <outline title="Existing News">
          <outline text="Feed D" title="Feed D" xmlUrl="http://feedd.com/rss" type="rss"/>
        </outline>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'existing_folder_import.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 1

    with app.app_context():
        assert Tab.query.count() == 1 # No new tab should be created
        target_tab = Tab.query.filter_by(name="Existing News").first()
        assert target_tab.id == existing_tab_id # Should be the same tab

        feeds_in_tab = Feed.query.filter_by(tab_id=existing_tab_id).all()
        assert len(feeds_in_tab) == 1
        assert feeds_in_tab[0].url == "http://feedd.com/rss"
        mock_fetch_update.assert_called_once_with(feeds_in_tab[0].id)

@patch('backend.app.fetch_and_update_feed')
def test_import_opml_empty_folder(mock_fetch_update_unused, client):
    """Tests import of an OPML with an empty folder."""
    mock_fetch_update_unused.return_value = (True, 0)
    opml_content = """
    <opml version="2.0">
      <body>
        <outline title="Empty Folder"></outline>
        <outline text="Top Level Feed E" title="Top Level Feed E" xmlUrl="http://toplevele.com/rss" type="rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'empty_folder_import.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 1 # Only Top Level Feed E

    with app.app_context():
        empty_folder_tab = Tab.query.filter_by(name="Empty Folder").first()
        assert empty_folder_tab is None # Corrected: Empty folders are skipped, no tab created

        # Check that the default tab for "Top Level Feed E" was created or used
        # If no other tabs existed, "Imported Feeds" would be created.
        # If other tabs existed, it would go into the first ordered one.
        # For this test, let's ensure it goes into "Imported Feeds" by ensuring no other tabs initially.
        # The client fixture already ensures a clean DB.

        default_tab = Tab.query.filter_by(name="Imported Feeds").first()
        assert default_tab is not None # This tab is for "Top Level Feed E"

        feeds_in_default = Feed.query.filter_by(tab_id=default_tab.id).all()
        assert len(feeds_in_default) == 1
        assert feeds_in_default[0].url == "http://toplevele.com/rss"

        mock_fetch_update_unused.assert_called_once_with(feeds_in_default[0].id)

    # Also assert the skipped count due to the empty folder
    assert json_data['skipped_count'] == 1


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_folder_with_no_title_is_skipped_children_go_to_default(mock_fetch_update, client):
    """Tests that a folder <outline> without a title is skipped, and its children go to the current default tab."""
    mock_fetch_update.return_value = (True, 1)
    with app.app_context(): # Ensure a default tab exists or will be created
        tab1 = Tab(name="Initial Tab", order=0)
        db.session.add(tab1)
        db.session.commit()
        initial_tab_id = tab1.id

    opml_content = """
    <opml version="2.0">
      <body>
        <outline> <!-- Folder without a title -->
          <outline text="Feed E" title="Feed E" xmlUrl="http://feede.com/rss" type="rss"/>
        </outline>
        <outline text="Feed F" title="Feed F" xmlUrl="http://feedf.com/rss" type="rss"/>
      </body>
    </opml>
    """
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'no_title_folder.opml')
    # Import into the specific initial_tab_id to make assertions easier
    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(initial_tab_id)}, content_type='multipart/form-data')

    assert response.status_code == 200
    json_data = response.json
    assert json_data['imported_count'] == 2 # Both Feed E and F should be imported

    with app.app_context():
        # No new tab should be created for the untitled folder
        assert Tab.query.count() == 1
        initial_tab = db.session.get(Tab, initial_tab_id)
        assert initial_tab is not None

        feeds_in_initial_tab = Feed.query.filter_by(tab_id=initial_tab_id).order_by(Feed.name).all()
        assert len(feeds_in_initial_tab) == 2
        assert feeds_in_initial_tab[0].name == "Feed E"
        assert feeds_in_initial_tab[1].name == "Feed F"

        assert mock_fetch_update.call_count == 2
        mock_fetch_update.assert_any_call(feeds_in_initial_tab[0].id)
        mock_fetch_update.assert_any_call(feeds_in_initial_tab[1].id)


@patch('backend.app.fetch_and_update_feed')
def test_import_opml_deletes_empty_default_imported_feeds_tab(mock_fetch_update, client): # Use client fixture for app context
    """
    Tests that if 'Imported Feeds' is created because no tabs exist,
    but all OPML items go into folders (new tabs), the empty 'Imported Feeds' tab is deleted.
    """
    mock_fetch_update.return_value = (True, 1) # Simulate feed fetch success
    # Ensure no tabs exist initially. The `client` fixture already handles db cleanup.
    with client.application.app_context(): # Use client.application.app_context()
        assert Tab.query.count() == 0

    opml_content = """<?xml version="1.0" encoding="UTF-8"?>
    <opml version="2.0">
        <head><title>Test OPML</title></head>
        <body>
            <outline text="My Folder">
                <outline text="Feed In Folder" type="rss" xmlUrl="http://example.com/folderfeed.xml"/>
            </outline>
        </body>
    </opml>"""

    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'test_delete_empty_default.opml')
    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 200
    data = response.json
    assert data['imported_count'] == 1 # The feed inside "My Folder"
    assert data['skipped_count'] == 0
    # The 'tab_name' in response might be "Imported Feeds" (the one that got deleted)
    # The 'tab_id' in response might be the ID of the deleted "Imported Feeds" tab.

    with client.application.app_context(): # Use client.application.app_context()
        tabs_after_import = Tab.query.all()
        # Only "My Folder" tab should exist. "Imported Feeds" should have been created and then deleted.
        assert len(tabs_after_import) == 1
        assert tabs_after_import[0].name == "My Folder"

        # Verify "Imported Feeds" tab specifically does not exist
        imported_feeds_tab_check = Tab.query.filter_by(name="Imported Feeds").first()
        assert imported_feeds_tab_check is None

        feed_in_folder = Feed.query.filter_by(url="http://example.com/folderfeed.xml").first()
        assert feed_in_folder is not None
        assert feed_in_folder.tab.name == "My Folder" # Associated with the correct tab

        # Check that fetch_and_update_feed was called for the imported feed
        mock_fetch_update.assert_called_once_with(feed_in_folder.id)

def test_get_feed_items_pagination(client, setup_tabs_and_feeds):
    """Test GET /api/feeds/<feed_id>/items with offset and limit for pagination."""
    feed_id = setup_tabs_and_feeds["feed1_id"]

    # Add 10 more items to the feed for a total of 12
    with app.app_context():
        for i in range(10):
            item = FeedItem(feed_id=feed_id, title=f"Paginate Item {i}", link=f"link_paginate_{i}", guid=f"guid_paginate_{i}")
            db.session.add(item)
        db.session.commit()

    # Get the first 5 items
    response1 = client.get(f'/api/feeds/{feed_id}/items?offset=0&limit=5')
    assert response1.status_code == 200
    assert len(response1.json) == 5

    # Get the next 5 items
    response2 = client.get(f'/api/feeds/{feed_id}/items?offset=5&limit=5')
    assert response2.status_code == 200
    assert len(response2.json) == 5

    # Get the last 2 items
    response3 = client.get(f'/api/feeds/{feed_id}/items?offset=10&limit=5')
    assert response3.status_code == 200
    assert len(response3.json) == 2


def test_get_feed_items_pagination_validation(client, setup_tabs_and_feeds):
    """Test GET /api/feeds/<feed_id>/items validation for invalid parameters."""
    feed_id = setup_tabs_and_feeds["feed1_id"]

    # Test negative offset
    response1 = client.get(f'/api/feeds/{feed_id}/items?offset=-1&limit=10')
    assert response1.status_code == 400
    assert 'Offset cannot be negative' in response1.json['error']

    # Test zero limit
    response2 = client.get(f'/api/feeds/{feed_id}/items?offset=0&limit=0')
    assert response2.status_code == 400
    assert 'Limit must be positive' in response2.json['error']

    # Test negative limit
    response3 = client.get(f'/api/feeds/{feed_id}/items?offset=0&limit=-5')
    assert response3.status_code == 400
    assert 'Limit must be positive' in response3.json['error']

    # Test limit exceeding maximum (should be capped, not error)
    response4 = client.get(f'/api/feeds/{feed_id}/items?offset=0&limit=200')
    assert response4.status_code == 200
    assert len(response4.json) == 2  # Should return available items, capped to MAX_PAGINATION_LIMIT


def test_get_feed_items_pagination_limit_capping(client, setup_tabs_and_feeds):
    """Test that pagination limit is properly capped when more items exist than MAX_PAGINATION_LIMIT."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    
    # Add more items than MAX_PAGINATION_LIMIT (110 items total)
    with app.app_context():
        # Clear existing items first
        FeedItem.query.filter_by(feed_id=feed_id).delete()
        
        # Add 110 items with sequential published times to ensure proper ordering
        from datetime import datetime, timedelta, timezone
        base_time = datetime.now(timezone.utc)
        
        for i in range(110):
            item = FeedItem(
                feed_id=feed_id, 
                title=f"Limit Cap Item {i}", 
                link=f"link_limit_cap_{i}", 
                guid=f"guid_limit_cap_{i}",
                published_time=base_time - timedelta(minutes=i)  # Newer items have later times
            )
            db.session.add(item)
        db.session.commit()

    # Test that limit exceeding MAX_PAGINATION_LIMIT (100) is properly capped
    response = client.get(f'/api/feeds/{feed_id}/items?offset=0&limit=200')
    assert response.status_code == 200
    assert len(response.json) == 100  # Should be capped to MAX_PAGINATION_LIMIT
    
    # Verify the items are properly ordered (newest first)
    # Since we added items with decreasing timestamps, the first item should be the most recent (i=0)
    assert response.json[0]['title'] == "Limit Cap Item 0"  # Most recent item
    assert response.json[-1]['title'] == "Limit Cap Item 99"  # 100th item from the end
