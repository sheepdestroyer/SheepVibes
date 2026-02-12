import pytest

def test_security_headers_present(client):
    """
    Test that the application sets the necessary security headers on responses.
    This ensures protection against common web vulnerabilities.
    """
    # Make a request to the root path
    response = client.get("/")

    # Assert status code is 200 (sanity check)
    assert response.status_code == 200

    # 1. X-Content-Type-Options: nosniff
    # Prevents MIME-sniffing, forcing the browser to follow the declared Content-Type.
    assert response.headers.get("X-Content-Type-Options") == "nosniff"

    # 2. X-Frame-Options: SAMEORIGIN
    # Prevents the site from being embedded in iframes on other domains (Clickjacking protection).
    # 'SAMEORIGIN' allows embedding on the same origin, which is safer than 'DENY' if needed,
    # and consistent with CSP frame-ancestors 'self'.
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"

    # 3. Referrer-Policy: strict-origin-when-cross-origin
    # Controls how much referrer information (URL) is sent with requests.
    # 'strict-origin-when-cross-origin' sends full URL for same-origin, but only origin for cross-origin HTTPS.
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # 4. Permissions-Policy: interest-cohort=()
    # explicitly disables FLoC (Federated Learning of Cohorts) tracking.
    permissions_policy = response.headers.get("Permissions-Policy", "")
    assert "interest-cohort=()" in permissions_policy

    # 5. Content-Security-Policy (CSP)
    # A powerful header to prevent XSS and other injections.
    csp = response.headers.get("Content-Security-Policy", "")
    assert csp is not None

    # Check for key CSP directives
    assert "default-src 'self'" in csp
    # Allow images from anywhere (needed for RSS feeds) and data: URIs
    assert "img-src * data:" in csp
    # Allow scripts only from self (no inline scripts allowed by default)
    assert "script-src 'self'" in csp
    # Allow styles from self and inline styles (needed for JS DOM manipulation of style attributes)
    assert "style-src 'self' 'unsafe-inline'" in csp
    # Restrict where the app can connect to (API/SSE)
    assert "connect-src 'self'" in csp
    # Prevent object embedding (Flash, etc.)
    assert "object-src 'none'" in csp
    # Modern replacement for X-Frame-Options
    assert "frame-ancestors 'self'" in csp
