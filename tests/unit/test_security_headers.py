from backend.app import app

EXPECTED_CSP = (

    "default-src 'self'; "

    "img-src * data:; "

    "script-src 'self'; "

    "style-src 'self' 'unsafe-inline'; "

    "connect-src 'self'; "

    "object-src 'none'; "

    "base-uri 'self'; "

    "form-action 'self'; "
    "frame-ancestors 'self'"
)

EXPECTED_PERMISSIONS_POLICY = "microphone=(), camera=(), geolocation=(), payment=(), usb=(), fullscreen=()"


def test_security_headers_present():
    """Verify that essential security headers are present in responses."""
    with app.test_client() as client:
        # Request a path that might not exist to ensure headers are added regardless of status
        response = client.get("/non-existent-path-for-security-test")

        # Content-Security-Policy
        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None, "Content-Security-Policy header is missing"
        assert csp == EXPECTED_CSP, (
            f"Content-Security-Policy header mismatch. Got: {csp}")

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
        assert permissions == EXPECTED_PERMISSIONS_POLICY, (
            f"Permissions-Policy header mismatch. Got: {permissions}")


def test_hsts_header_on_secure_request():
    """Verify HSTS header is present on HTTPS requests."""
    with app.test_client() as client:
        # Simulate a secure request by setting the base_url scheme
        response = client.get("/non-existent-path-for-security-test",
                              base_url="https://localhost")
        hsts = response.headers.get("Strict-Transport-Security")
        assert hsts is not None, (
            "Strict-Transport-Security header is missing on secure request")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts


def test_hsts_header_not_on_insecure_request():
    """Verify HSTS header is NOT present on HTTP requests."""
    with app.test_client() as client:
        response = client.get("/non-existent-path-for-security-test",
                              base_url="http://localhost")
        hsts = response.headers.get("Strict-Transport-Security")
        assert hsts is None, (
            "Strict-Transport-Security header should not be present on insecure request"
        )
