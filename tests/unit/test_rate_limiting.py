import pytest
import io
from unittest.mock import patch, MagicMock
from backend.app import app, db
from backend.extensions import limiter
from backend.models import Tab

@pytest.fixture
def client():
    """Configures the Flask app for rate limit testing."""
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = True
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"

    # Force enable limiter extension
    limiter.enabled = True

    # Re-initialize app with the new config to ensure handlers are registered
    # because app.py disables it by default in testing mode
    limiter.init_app(app)

    # Reset storage
    try:
        if hasattr(limiter, "_storage") and limiter._storage:
            limiter._storage.reset()
    except Exception:
        pass

    # Setup DB
    with app.app_context():
        db.create_all()
        # Create default tab required by add_feed
        if not Tab.query.first():
            db.session.add(Tab(name="Default", order=0))
            db.session.commit()

    with app.test_client() as client:
        yield client

    # Teardown
    limiter.enabled = False # Reset global state
    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_rate_limit_add_feed(client):
    """Test that adding feeds is rate limited (10 per minute)."""
    with patch("backend.blueprints.feeds.fetch_feed") as mock_fetch:
        mock_fetch.return_value = None

        for i in range(10):
            response = client.post("/api/feeds", json={"url": f"http://example.com/feed{i}"})
            assert response.status_code != 429

        response = client.post("/api/feeds", json={"url": "http://example.com/feed11"})
        assert response.status_code == 429

def test_rate_limit_opml_import(client):
    """Test that OPML import is rate limited (5 per hour)."""
    with patch("backend.blueprints.opml._validate_opml_file_request") as mock_validate, \
         patch("backend.blueprints.opml.import_opml_service") as mock_service:

        file_mock = MagicMock()
        mock_validate.return_value = (file_mock, None)

        # We need to return the expected tuple structure (result, error)
        # where result is a dict and error is None
        mock_service.return_value = ({"imported_count": 0, "skipped_count": 0, "message": "Success"}, None)

        for i in range(5):
            data = {'file': (io.BytesIO(b'<opml></opml>'), 'test.opml')}
            response = client.post("/api/opml/import", data=data, content_type='multipart/form-data')
            assert response.status_code != 429

        data = {'file': (io.BytesIO(b'<opml></opml>'), 'test.opml')}
        response = client.post("/api/opml/import", data=data, content_type='multipart/form-data')
        assert response.status_code == 429
