import pytest
import os

# Set testing mode before importing app to avoid database connection issues
os.environ['TESTING'] = 'true'

from backend.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers(client):
    """Test that security headers are set on responses."""
    response = client.get('/')

    # Check for X-Content-Type-Options
    assert response.headers.get('X-Content-Type-Options') == 'nosniff', \
        "X-Content-Type-Options header missing or incorrect"

    # Check for X-Frame-Options
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN', \
        "X-Frame-Options header missing or incorrect"

    # Check for Referrer-Policy
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin', \
        "Referrer-Policy header missing or incorrect"

    # Check for Content-Security-Policy
    csp = response.headers.get('Content-Security-Policy')
    assert csp is not None, "Content-Security-Policy header missing"

    expected_directives = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "img-src 'self' data: https:"
    ]

    for directive in expected_directives:
        assert directive in csp, f"CSP missing directive: {directive}"
