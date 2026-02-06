import pytest


def test_security_headers(client):
    """Test that all required security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # CSP
    assert "Content-Security-Policy" in headers
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "connect-src 'self'" in csp

    # Other headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert headers.get("Permissions-Policy") == "interest-cohort=()"
