import pytest

def test_security_headers_present(client):
    """Test that security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    # Check for X-Frame-Options
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Check for X-Content-Type-Options
    assert response.headers.get("X-Content-Type-Options") == "nosniff"

    # Check for Referrer-Policy
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Check for Content-Security-Policy
    csp = response.headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "img-src 'self' data: https:" in csp
