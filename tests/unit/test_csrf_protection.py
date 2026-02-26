import pytest

from backend.app import app


@pytest.fixture
def enable_csrf():
    """Temporarily enable CSRF protection for testing."""
    original_value = app.config.get("CSRF_ENABLED")
    app.config["CSRF_ENABLED"] = True
    yield
    if original_value is None:
        del app.config["CSRF_ENABLED"]
    else:
        app.config["CSRF_ENABLED"] = original_value


def test_csrf_protection_missing_token(client, enable_csrf):
    """Test that requests without CSRF token are rejected."""
    # Ensure cookie is set
    client.get("/")

    # POST request without token header should fail
    # Note: client automatically sends cookies, but we are missing the header
    response = client.post("/api/tabs", json={"name": "Test Tab"})
    assert response.status_code == 403
    assert b"CSRF token missing" in response.data


def test_csrf_protection_invalid_token(client, enable_csrf):
    """Test that requests with invalid CSRF token are rejected."""
    client.get("/")

    # Send request with invalid header
    response = client.post("/api/tabs",
                           json={"name": "Test Tab"},
                           headers={"X-CSRFToken": "invalid_token"})
    assert response.status_code == 403
    assert b"CSRF token missing or invalid" in response.data


def test_csrf_protection_valid_token(client, enable_csrf):
    """Test that requests with valid CSRF token are accepted."""
    # 1. GET request to establish session and get cookie
    client.get("/")

    # 2. Retrieve the cookie value
    csrf_token = None
    # Try getting cookie using the test client's method if available, or iterate jar
    cookie = client.get_cookie("csrf_token")
    if cookie:
        csrf_token = cookie.value

    assert csrf_token is not None, "CSRF cookie not found"

    # 3. POST request with correct header
    response = client.post("/api/tabs",
                           json={"name": "CSRF Test Tab"},
                           headers={"X-CSRFToken": csrf_token})

    # This should succeed
    assert response.status_code == 201


def test_csrf_safe_methods(client, enable_csrf):
    """Test that GET requests do not require CSRF token."""
    response = client.get("/api/tabs")
    assert response.status_code == 200
