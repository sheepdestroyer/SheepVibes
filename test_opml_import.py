import io
import logging
import pytest
from backend.app import app, db
from backend.models import Tab, Feed

logger = logging.getLogger(__name__)

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_import(client, mocker):
    """Test the OPML import endpoint using the Flask test client."""
    url = '/api/opml/import'
    logger.info(f"Testing OPML import at: {url}")

    # Use an in-memory file object
    opml_content = b'<opml version="1.0"><body><outline text="Test Feed" xmlUrl="http://example.com/feed" /></body></opml>'
    opml_file = io.BytesIO(opml_content)
    
    data = {
        'file': (opml_file, 'test_feeds.opml')
    }

    # Mock the internal fetch_and_update_feed to avoid actual network calls
    mocker.patch('backend.app.fetch_and_update_feed')

    response = client.post(url, data=data, content_type='multipart/form-data')
    
    logger.info(f"Status Code: {response.status_code}")
    assert response.status_code == 200
    
    response_data = response.get_json()
    logger.info(f"Response: {response_data}")

    assert response_data.get('imported_count', 0) == 1
    assert response_data.get('skipped_count', 0) == 0
    
    # Verify DB state
    with app.app_context():
        feed = Feed.query.filter_by(url="http://example.com/feed").first()
        assert feed is not None
        assert feed.name == "Test Feed"

    logger.info("Test PASSED")
