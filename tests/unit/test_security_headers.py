import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers(client):
    """Test that all security headers are present and correctly configured."""
    response = client.get('/')
    headers = response.headers

    # Check X-Content-Type-Options
    assert headers.get('X-Content-Type-Options') == 'nosniff'

    # Check X-Frame-Options
    assert headers.get('X-Frame-Options') == 'SAMEORIGIN'

    # Check Referrer-Policy
    assert headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    # Check Permissions-Policy
    assert headers.get('Permissions-Policy') == 'interest-cohort=()'

    # Check Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    assert csp is not None

    # Check specific CSP directives
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "img-src 'self' data: https:" in csp
    assert "connect-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
