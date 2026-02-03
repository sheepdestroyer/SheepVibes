def test_security_headers_present(client):
    """
    Test that the application responses include important security headers.
    """
    response = client.get("/")
    assert response.status_code == 200

    headers = response.headers

    # Sentinel: X-Content-Type-Options: nosniff
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # Sentinel: X-Frame-Options: SAMEORIGIN
    # Prevents clickjacking
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"

    # Sentinel: Referrer-Policy
    # Controls how much referrer information is sent
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Sentinel: Content-Security-Policy (CSP)
    # Mitigates XSS and other attacks
    csp = headers.get("Content-Security-Policy")
    assert csp is not None

    # Check for critical CSP directives
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp

    # Sentinel: Permissions-Policy
    # Blocks FLoC / Topics API
    assert "interest-cohort=()" in headers.get("Permissions-Policy", "")
