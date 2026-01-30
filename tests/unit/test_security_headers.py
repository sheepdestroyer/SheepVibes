import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_security_headers_present(client):
    response = client.get('/')
    headers = response.headers

    # Check for X-Content-Type-Options
    assert headers.get('X-Content-Type-Options') == 'nosniff'

    # Check for X-Frame-Options
    assert headers.get('X-Frame-Options') == 'SAMEORIGIN'

    # Check for Referrer-Policy
    assert headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    # Check for Content-Security-Policy
    csp = headers.get('Content-Security-Policy')
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "img-src 'self' data: https:" in csp
    # Check for script-src and style-src as well
    assert "script-src 'self'" in csp
    # Allow inline styles as per requirements
    assert "style-src 'self' 'unsafe-inline'" in csp
