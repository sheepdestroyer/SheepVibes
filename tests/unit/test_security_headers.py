import pytest

from backend.app import app


@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    app.config["TESTING"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["CACHE_TYPE"] = "SimpleCache"

    with app.test_client() as client:
        yield client


def test_security_headers_present(client):
    """Test that all required security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # Check for Content-Security-Policy
    assert "Content-Security-Policy" in headers, (
        "Content-Security-Policy header missing"
    )
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp

    # Check for X-Content-Type-Options
    assert "X-Content-Type-Options" in headers, "X-Content-Type-Options header missing"
    assert headers["X-Content-Type-Options"] == "nosniff"

    # Check for X-Frame-Options
    assert "X-Frame-Options" in headers, "X-Frame-Options header missing"
    assert headers["X-Frame-Options"] in ["DENY", "SAMEORIGIN"]

    # Check for Referrer-Policy
    assert "Referrer-Policy" in headers, "Referrer-Policy header missing"

    # Check for Permissions-Policy (or Feature-Policy for older browser compat if needed, but Permissions-Policy is standard now)
    assert "Permissions-Policy" in headers, "Permissions-Policy header missing"
