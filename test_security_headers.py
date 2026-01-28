import logging
from backend.app import app

logger = logging.getLogger(__name__)

def test_security_headers(client):
    """Test that security headers are present in the response."""
    # Test main page
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp

    # Test API endpoint
    response_api = client.get("/api/tabs")
    assert response_api.status_code == 200

    headers_api = response_api.headers
    assert headers_api["X-Content-Type-Options"] == "nosniff"
    assert headers_api["X-Frame-Options"] == "DENY"
    assert headers_api["Content-Security-Policy"] == headers["Content-Security-Policy"]
