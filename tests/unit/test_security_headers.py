def test_security_headers_present(client):
    """Test that all required security headers are present in the response."""
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # Check X-Content-Type-Options
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # Check X-Frame-Options
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Check X-XSS-Protection
    assert headers.get("X-XSS-Protection") == "1; mode=block"

    # Check Content-Security-Policy
    csp = headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp

    # Check Referrer-Policy
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Check Permissions-Policy
    assert headers.get("Permissions-Policy") == "interest-cohort=()"
