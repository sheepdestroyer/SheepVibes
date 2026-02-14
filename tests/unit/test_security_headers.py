import pytest

from backend.app import app


def test_security_headers_present():
    """Verify that essential security headers are present in responses."""
    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200

        # Content-Security-Policy
        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None, "Content-Security-Policy header is missing"
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'self'" in csp
        # Verify allow-list for images (data: and *)
        assert "img-src * data:" in csp or "img-src 'self' data: *" in csp

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
