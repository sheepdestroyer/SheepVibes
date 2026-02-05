import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    """Test that all required security headers are present in responses."""
    response = client.get('/')
    headers = response.headers

    # Check for specific headers and their expected values
    assert headers.get('X-Content-Type-Options') == 'nosniff'
    assert headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    # Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp # Needed for JS style manipulation as per memory
    assert "img-src 'self' data: https:" in csp # Needed for external RSS images
    assert "connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*" in csp

    # Permissions-Policy
    assert headers.get('Permissions-Policy') == 'interest-cohort=()'
