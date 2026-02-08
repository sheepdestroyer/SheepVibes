import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    """Test that security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # X-Content-Type-Options
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # X-Frame-Options
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Referrer-Policy
    # Allow strict-origin-when-cross-origin or no-referrer, strict-origin-when-cross-origin is preferred for modern apps
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Permissions-Policy
    # Should disable FLoC/interest-cohort
    assert headers.get("Permissions-Policy") == "interest-cohort=()"

    # Content-Security-Policy
    csp = headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    # Allow data: and https: images (for feed icons/images)
    assert "img-src 'self' data: https:" in csp
    # Allow self scripts
    assert "script-src 'self'" in csp
    # Allow inline styles (as used by frontend currently)
    assert "style-src 'self' 'unsafe-inline'" in csp
    # Allow self connections (for API/SSE)
    assert "connect-src 'self'" in csp
