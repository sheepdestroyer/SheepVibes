import pytest

from backend.app import app


@pytest.fixture
def enable_csrf():
    """Enable CSRF protection for the duration of the test."""
    original_value = app.config.get("CSRF_ENABLED")
    app.config["CSRF_ENABLED"] = True
    yield
    # Restore original value
    if original_value is not None:
        app.config["CSRF_ENABLED"] = original_value
    else:
        app.config.pop("CSRF_ENABLED", None)


def test_csrf_protection_missing_token(client, enable_csrf):
    """Test that POST request fails without CSRF token."""
    response = client.post("/api/tabs", json={"name": "New Tab"})
    assert response.status_code == 403
    assert b"CSRF token missing or invalid" in response.data


def test_csrf_protection_missing_header(client, enable_csrf):
    """Test that POST request fails with cookie but missing header."""
    # First make a request to get the CSRF cookie
    client.get("/")

    # Verify cookie is present using Flask's get_cookie method
    csrf_cookie = client.get_cookie("csrf_token")
    assert csrf_cookie is not None, "CSRF cookie not set by server"

    # POST without X-CSRFToken header
    response = client.post("/api/tabs", json={"name": "Fail Tab"})
    assert response.status_code == 403


def test_csrf_protection_invalid_token(client, enable_csrf):
    """Test that POST request fails with mismatched token."""
    # Set a known cookie value
    client.set_cookie("csrf_token", "real_token_value")

    # POST with mismatching header
    response = client.post(
        "/api/tabs",
        json={"name": "Fail Tab"},
        headers={"X-CSRFToken": "fake_token_value"},
    )
    assert response.status_code == 403


def test_csrf_protection_success(client, enable_csrf):
    """Test that POST request succeeds with valid token."""
    # Get the CSRF cookie
    client.get("/")

    # Extract the cookie value using get_cookie
    csrf_cookie = client.get_cookie("csrf_token")
    assert csrf_cookie is not None
    token = csrf_cookie.value

    # POST with matching header
    response = client.post(
        "/api/tabs", json={"name": "Success Tab"}, headers={"X-CSRFToken": token}
    )
    assert response.status_code == 201
