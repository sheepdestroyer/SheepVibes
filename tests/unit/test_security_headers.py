import pytest
import os
from backend.app import app
from backend.extensions import db

@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    app.config["TESTING"] = True
    app.config["CACHE_TYPE"] = "SimpleCache"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with app.app_context():
        db.create_all()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_security_headers_presence_root(client):
    """Test that security headers are present on the root endpoint."""
    response = client.get("/")
    # If index.html is missing (e.g. build artifact), this might be 404, but headers should still be there.
    # However, app.py uses send_from_directory, which might 404 if file missing.
    # But usually headers are added via after_request regardless of status code.

    headers = response.headers

    # Check for X-Content-Type-Options
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # Check for X-Frame-Options
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Check for Referrer-Policy
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Check for Permissions-Policy
    assert headers.get("Permissions-Policy") == "interest-cohort=()"

    # Check for Content-Security-Policy
    csp = headers.get("Content-Security-Policy")
    assert csp is not None

    # Check critical CSP directives
    assert "default-src 'self'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp

def test_security_headers_presence_api(client):
    """Test that security headers are present on API endpoints."""
    # Use an endpoint that doesn't require auth or complex setup
    response = client.get("/api/tabs")

    headers = response.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("Content-Security-Policy") is not None
