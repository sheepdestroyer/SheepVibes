import pytest


def test_security_headers_present(client):
    """
    Verifies that security headers are correctly present in the response.
    """
    response = client.get("/")
    headers = response.headers

    # We assert they are present, so this test fails if they are missing
    assert "Content-Security-Policy" in headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "connect-src 'self'" in csp
