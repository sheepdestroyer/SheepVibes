import io
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from backend.blueprints.feeds import feeds_bp
from backend.blueprints.opml import opml_bp
from backend.extensions import cache, db, limiter
from backend.models import Tab


@pytest.fixture
def client():
    """Configures a fresh Flask app for rate limit testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = True
    app.config["RATELIMIT_STORAGE_URI"] = "memory://"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions with the new app
    db.init_app(app)
    cache.init_app(app)
    limiter.init_app(app)

    # Register blueprints that have rate limits
    app.register_blueprint(feeds_bp)
    app.register_blueprint(opml_bp)

    # Setup DB
    with app.app_context():
        db.create_all()
        # Create default tab required by add_feed logic
        if not Tab.query.first():
            db.session.add(Tab(name="Default", order=0))
            db.session.commit()

    with app.test_client() as client:
        yield client

    # Teardown not strictly needed as app is local, but good practice to close sessions
    with app.app_context():
        db.session.remove()
        db.drop_all()


def test_rate_limit_add_feed(client):
    """Test that adding feeds is rate limited (10 per minute)."""
    with patch("backend.blueprints.feeds.fetch_feed") as mock_fetch:
        mock_fetch.return_value = None

        # 10 requests should succeed (201 Created)
        for i in range(10):
            response = client.post("/api/feeds",
                                   json={"url": f"http://example.com/feed{i}"})
            assert response.status_code != 429

        # The 11th request should be rate limited
        response = client.post("/api/feeds",
                               json={"url": "http://example.com/feed11"})
        assert response.status_code == 429


def test_rate_limit_opml_import(client):
    """Test that OPML import is rate limited (5 per hour)."""
    with (
            patch("backend.blueprints.opml._validate_opml_file_request") as
            mock_validate,
            patch("backend.blueprints.opml.import_opml_service") as
            mock_service,
    ):
        file_mock = MagicMock()
        mock_validate.return_value = (file_mock, None)
        mock_service.return_value = (
            {
                "imported_count": 0,
                "skipped_count": 0,
                "message": "Success"
            },
            None,
        )

        for i in range(5):
            data = {"file": (io.BytesIO(b"<opml></opml>"), "test.opml")}
            response = client.post("/api/opml/import",
                                   data=data,
                                   content_type="multipart/form-data")
            assert response.status_code != 429

        data = {"file": (io.BytesIO(b"<opml></opml>"), "test.opml")}
        response = client.post("/api/opml/import",
                               data=data,
                               content_type="multipart/form-data")
        assert response.status_code == 429
