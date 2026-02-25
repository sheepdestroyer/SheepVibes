import pytest
from backend.app import app

@pytest.fixture
def enable_csrf():
    """Temporarily enables CSRF protection for testing."""
    original_value = app.config.get("CSRF_ENABLED")
    app.config["CSRF_ENABLED"] = True
    yield
    if original_value is None:
        app.config.pop("CSRF_ENABLED", None)
    else:
        app.config["CSRF_ENABLED"] = original_value

def test_csrf_protection_disabled_by_default_in_tests(client):
    """Verify that CSRF protection is disabled in tests normally."""
    # Should succeed without token
    response = client.post("/api/tabs", json={"name": "No CSRF Tab"})
    assert response.status_code == 201

def test_csrf_missing_token(client, enable_csrf):
    """Test POST request without CSRF token fails when protection enabled."""
    # Ensure no cookies are set initially (though client is fresh per test usually)
    # Make a request that triggers validation
    response = client.post("/api/tabs", json={"name": "Test Tab"})
    assert response.status_code == 403
    assert "CSRF validation failed" in response.json["error"]

def test_csrf_valid_token(client, enable_csrf):
    """Test POST request with valid CSRF token succeeds."""
    # 1. GET request to receive the cookie
    client.get("/")

    # 2. Extract the cookie value
    # Werkzeug 2.3+ test client has get_cookie method, but fallback to cookie_jar iteration for compatibility
    csrf_token = None
    if hasattr(client, 'get_cookie'):
        cookie = client.get_cookie('csrf_token')
        if cookie:
            csrf_token = cookie.value

    if not csrf_token:
        # Fallback for older Werkzeug
        for cookie in client.cookie_jar:
            if cookie.name == 'csrf_token':
                csrf_token = cookie.value
                break

    assert csrf_token is not None, "CSRF cookie not found"

    # 3. POST with the token in header
    response = client.post(
        "/api/tabs",
        json={"name": "CSRF Tab"},
        headers={"X-CSRFToken": csrf_token}
    )
    assert response.status_code == 201

def test_csrf_mismatch_token(client, enable_csrf):
    """Test POST request with mismatched token fails."""
    client.get("/")

    response = client.post(
        "/api/tabs",
        json={"name": "Fail Tab"},
        headers={"X-CSRFToken": "wrong_token"}
    )
    assert response.status_code == 403

def test_csrf_cookie_attributes(client):
    """Test that the CSRF cookie has correct security attributes."""
    response = client.get("/")

    # Check Set-Cookie header
    cookie_headers = [h[1] for h in response.headers if h[0] == 'Set-Cookie']
    csrf_cookie_header = next((h for h in cookie_headers if 'csrf_token' in h), None)

    assert csrf_cookie_header is not None
    assert "SameSite=Lax" in csrf_cookie_header
    # HttpOnly should NOT be present (since it's False)
    assert "HttpOnly" not in csrf_cookie_header
