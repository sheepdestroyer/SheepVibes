import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    """Test that essential security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # Content-Security-Policy
    assert "Content-Security-Policy" in headers
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    # We allow unsafe-inline styles as per memory
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "connect-src 'self'" in csp

    # X-Content-Type-Options
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # X-Frame-Options
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Referrer-Policy
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
