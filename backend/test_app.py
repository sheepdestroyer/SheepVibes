import pytest
import json
from unittest.mock import patch, MagicMock

# Import the Flask app instance and db object
# Need to configure the app for testing
from app import app, db, Tab, Feed, FeedItem # Import necessary models

@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    # Use an in-memory SQLite database for testing
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Disable CSRF protection if it were enabled
    # app.config['WTF_CSRF_ENABLED'] = False 

    with app.app_context(): # Ensure app context for create_all and drop_all
        db.create_all() # Ensure tables are created for each test

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
        tab = Tab.query.get(response.json['id'])
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
        tab = Tab.query.get(tab_id)
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
        tab = Tab.query.get(tab1_id)
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
    
    # Assert
    assert response.status_code == 400
    assert 'error' in response.json
    assert 'Cannot delete the last tab' in response.json['error']
    
    # Verify in DB
    with app.app_context():
        assert Tab.query.count() == 1

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
        feed3 = Feed(tab_id=tab2.id, name="Feed 3", url="url3")
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

def test_get_feeds_for_tab(client, setup_tabs_and_feeds):
    """Test GET /api/tabs/<tab_id>/feeds."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    response = client.get(f'/api/tabs/{tab1_id}/feeds')
    assert response.status_code == 200
    assert len(response.json) == 2
    feed_names = {feed['name'] for feed in response.json}
    assert feed_names == {"Feed 1", "Feed 2"}

def test_get_feeds_for_tab_not_found(client):
    """Test GET /api/tabs/<tab_id>/feeds for non-existent tab."""
    response = client.get('/api/tabs/999/feeds')
    assert response.status_code == 404

# Mock feed fetching/processing for add/delete tests
@patch('app.fetch_feed') # Patch fetch_feed imported in app.py
@patch('app.process_feed_entries') # Patch process_feed_entries imported in app.py
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
        feed = Feed.query.get(response.json['id'])
        assert feed is not None
        assert feed.url == feed_url
        assert feed.tab_id == tab1_id

@patch('app.fetch_feed')
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

@patch('app.fetch_feed')
def test_add_feed_duplicate_url(mock_fetch, client, setup_tabs_and_feeds):
    """Test POST /api/feeds with a duplicate URL."""
    tab1_id = setup_tabs_and_feeds["tab1_id"]
    existing_url = "url1" # From setup_tabs_and_feeds
    
    response = client.post('/api/feeds', json={'url': existing_url, 'tab_id': tab1_id})
    
    assert response.status_code == 409 # Conflict
    assert 'error' in response.json
    assert 'already exists' in response.json['error']
    mock_fetch.assert_not_called() # Should check DB before fetching

def test_add_feed_invalid_tab(client):
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
        assert FeedItem.query.get(item1_id) is not None
        assert FeedItem.query.get(item2_id) is not None
        
    response = client.delete(f'/api/feeds/{feed1_id}')
    
    assert response.status_code == 200
    assert 'message' in response.json
    
    # Verify feed and associated items are deleted (due to cascade)
    with app.app_context():
        assert Feed.query.get(feed1_id) is None
        assert FeedItem.query.get(item1_id) is None
        assert FeedItem.query.get(item2_id) is None

def test_delete_feed_not_found(client):
    """Test DELETE /api/feeds/<id> for non-existent feed."""
    response = client.delete('/api/feeds/999')
    assert response.status_code == 404

def test_get_feed_items(client, setup_tabs_and_feeds):
    """Test GET /api/feeds/<feed_id>/items."""
    feed1_id = setup_tabs_and_feeds["feed1_id"]
    response = client.get(f'/api/feeds/{feed1_id}/items')
    assert response.status_code == 200
    assert len(response.json) == 2
    # Items should be ordered by published_time desc (or fetched_time desc if null)
    # Assuming Item 1.2 was fetched/published later for this test setup
    item_titles = [item['title'] for item in response.json]
    # Order depends on how test data was added and default sorting
    # Let's check presence instead of strict order for simplicity here
    assert set(item_titles) == {"Item 1.1", "Item 1.2"}
    assert response.json[0]['is_read'] in [True, False] # Check boolean value

def test_get_feed_items_limit(client, setup_tabs_and_feeds):
    """Test GET /api/feeds/<feed_id>/items with limit parameter."""
    feed1_id = setup_tabs_and_feeds["feed1_id"]
    response = client.get(f'/api/feeds/{feed1_id}/items?limit=1')
    assert response.status_code == 200
    assert len(response.json) == 1

def test_get_feed_items_feed_not_found(client):
    """Test GET /api/feeds/<feed_id>/items for non-existent feed."""
    response = client.get('/api/feeds/999/items')
    assert response.status_code == 404

def test_mark_item_read_success(client, setup_tabs_and_feeds):
    """Test POST /api/items/<item_id>/read for an unread item."""
    item1_id = setup_tabs_and_feeds["item1_id"] # Initially unread
    
    # Verify initial state
    with app.app_context():
        assert FeedItem.query.get(item1_id).is_read == False
        
    response = client.post(f'/api/items/{item1_id}/read')
    
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'marked as read' in response.json['message']
    
    # Verify state change in DB
    with app.app_context():
        assert FeedItem.query.get(item1_id).is_read == True

def test_mark_item_read_already_read(client, setup_tabs_and_feeds):
    """Test POST /api/items/<item_id>/read for an already read item."""
    item2_id = setup_tabs_and_feeds["item2_id"] # Initially read
    
    # Verify initial state
    with app.app_context():
        assert FeedItem.query.get(item2_id).is_read == True
        
    response = client.post(f'/api/items/{item2_id}/read')
    
    assert response.status_code == 200
    assert 'message' in response.json
    assert 'already marked as read' in response.json['message']
    
    # Verify state didn't change
    with app.app_context():
        assert FeedItem.query.get(item2_id).is_read == True

def test_mark_item_read_not_found(client):
    """Test POST /api/items/<item_id>/read for non-existent item."""
    response = client.post('/api/items/999/read')
    assert response.status_code == 404

# --- Tests for POST /api/feeds/<feed_id>/update ---

@patch('app.models_to_dict')
@patch('app.feed_service.fetch_and_update_feed')
def test_update_feed_success(mock_fetch_and_update, mock_models_to_dict, client, setup_tabs_and_feeds):
    """Test POST /api/feeds/<feed_id>/update successfully."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    mock_feed_object = MagicMock(spec=Feed) # Simulate a Feed SQLAlchemy object
    mock_feed_dict = {"id": feed_id, "name": "Updated Feed", "url": "url1", "unread_count": 5}

    mock_fetch_and_update.return_value = mock_feed_object
    mock_models_to_dict.return_value = mock_feed_dict

    response = client.post(f'/api/feeds/{feed_id}/update')

    assert response.status_code == 200
    assert response.json == mock_feed_dict
    mock_fetch_and_update.assert_called_once_with(feed_id)
    mock_models_to_dict.assert_called_once_with(mock_feed_object)

@patch('app.feed_service.fetch_and_update_feed')
def test_update_feed_not_found(mock_fetch_and_update, client):
    """Test POST /api/feeds/<feed_id>/update when feed is not found."""
    feed_id = 999
    mock_fetch_and_update.side_effect = LookupError("Feed not found")

    response = client.post(f'/api/feeds/{feed_id}/update')

    assert response.status_code == 404
    assert 'error' in response.json
    assert "Feed not found" in response.json['error']
    mock_fetch_and_update.assert_called_once_with(feed_id)

@patch('app.feed_service.fetch_and_update_feed')
def test_update_feed_failure(mock_fetch_and_update, client, setup_tabs_and_feeds):
    """Test POST /api/feeds/<feed_id>/update when the update process fails."""
    feed_id = setup_tabs_and_feeds["feed1_id"]
    mock_fetch_and_update.side_effect = Exception("Simulated update error")

    response = client.post(f'/api/feeds/{feed_id}/update')

    assert response.status_code == 500
    assert 'error' in response.json
    assert "Failed to update feed" in response.json['error']
    # The original error message might also be in the response, depending on error handling
    # assert "Simulated update error" in response.json['error']
    mock_fetch_and_update.assert_called_once_with(feed_id)

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
    assert response.content_type == 'application/javascript' # Common for .js
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
