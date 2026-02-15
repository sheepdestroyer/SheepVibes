from backend.app import app


def test_security_headers_present():
    """Verify that essential security headers are present in responses."""
    with app.test_client() as client:
        # Request a path that might not exist to ensure headers are added regardless of status
        response = client.get("/non-existent-path-for-security-test")

        # Content-Security-Policy
        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None, "Content-Security-Policy header is missing"
        assert "default-src 'self'" in csp
        assert "img-src * data:" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp
        assert "connect-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'self'" in csp

        # X-Content-Type-Options
        assert response.headers.get("X-Content-Type-Options") == "nosniff", (
            "X-Content-Type-Options header is missing or incorrect")

        # X-Frame-Options
        assert response.headers.get("X-Frame-Options") == "SAMEORIGIN", (
            "X-Frame-Options header is missing or incorrect")

        # Referrer-Policy
        referrer = response.headers.get("Referrer-Policy")
        assert referrer is not None, "Referrer-Policy header is missing"
        assert "strict-origin-when-cross-origin" in referrer

        # Permissions-Policy
        permissions = response.headers.get("Permissions-Policy")
        assert permissions is not None, "Permissions-Policy header is missing"
        assert "microphone=()" in permissions
        assert "camera=()" in permissions
        assert "geolocation=()" in permissions
