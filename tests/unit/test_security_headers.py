import pytest

from backend.app import app


@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    # Base test config
    app.config["TESTING"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = False

    # Use SimpleCache
    app.config["CACHE_TYPE"] = "SimpleCache"

    with app.test_client() as client:
        yield client


def test_security_headers_presence(client):
    """Test that all required security headers are present in the response."""
    response = client.get("/")

    # Assert status code is 200 (sanity check that app is working)
    assert response.status_code == 200

    headers = response.headers

    # Check for Security Headers
    assert "Content-Security-Policy" in headers, "CSP header missing"
    assert "X-Content-Type-Options" in headers, "X-Content-Type-Options header missing"
    assert "X-Frame-Options" in headers, "X-Frame-Options header missing"
    assert "Referrer-Policy" in headers, "Referrer-Policy header missing"
    assert "Permissions-Policy" in headers, "Permissions-Policy header missing"

    # Verify specific values (as per Sentinel requirements)
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] in ["DENY", "SAMEORIGIN"]
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "interest-cohort=()"

    # Verify CSP content
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "connect-src 'self'" in csp
    # Check that object-src is none or not present (default-src self implies it's restricted if not overridden, but best practice is object-src 'none')
    # For now, just checking the positives required.
