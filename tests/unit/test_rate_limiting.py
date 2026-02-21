from unittest.mock import patch

import pytest

from backend.app import app, cache, db, limiter
from backend.models import Tab


@pytest.fixture
def rate_limit_client():
    """Configures the Flask app for rate limit testing."""
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = True
    limiter.enabled = True
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Reset Flask app's internal state
    app._got_first_request = False

    # Initialize extensions if needed (already done in app.py but config changed)
    # Limiter needs to pick up the new config?
    # Actually, modifying app.config after init_app might not affect Limiter immediately
    # if it reads config during init.
    # Flask-Limiter 3.x reads config dynamically usually?
    # But storage backend might be instantiated once.

    # Re-initialize limiter to be safe with new storage
    # limiter.init_app(app)

    with app.app_context():
        db.create_all()
        cache.clear()

        # Create a default tab for feeds
        tab = Tab(name="Test Tab", order=0)
        db.session.add(tab)
        db.session.commit()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_export_opml_rate_limit(rate_limit_client):
    """Test rate limiting on OPML export (10/minute)."""
    # Hit the endpoint 10 times
    for _ in range(10):
        response = rate_limit_client.get("/api/opml/export")
        assert response.status_code != 429

    # The 11th request should be rate limited
    response = rate_limit_client.get("/api/opml/export")
    assert response.status_code == 429
    assert "Too Many Requests" in response.text or "429" in response.status


@patch("backend.blueprints.feeds.fetch_feed")
def test_add_feed_rate_limit(mock_fetch, rate_limit_client):
    """Test rate limiting on Add Feed (10/minute)."""
    mock_fetch.return_value = None  # Simulate fetch failure to keep it fast

    url = "/api/feeds"
    # We need a valid tab_id, assumed 1 from fixture

    for i in range(10):
        # Use unique URLs to avoid potential logic errors, though 409 is also counted
        data = {"url": f"http://example.com/feed{i}", "tab_id": 1}
        response = rate_limit_client.post(url, json=data)
        assert response.status_code != 429

    # The 11th request
    data = {"url": "http://example.com/feed11", "tab_id": 1}
    response = rate_limit_client.post(url, json=data)
    assert response.status_code == 429


def test_api_update_all_feeds_rate_limit(rate_limit_client):
    """Test rate limiting on Update All Feeds (1/minute)."""
    # First request - OK
    with patch("backend.blueprints.feeds.update_all_feeds") as mock_update:
        mock_update.return_value = (0, 0, set())
        response = rate_limit_client.post("/api/feeds/update-all")
        assert response.status_code == 200

    # Second request - Blocked
    response = rate_limit_client.post("/api/feeds/update-all")
    assert response.status_code == 429
