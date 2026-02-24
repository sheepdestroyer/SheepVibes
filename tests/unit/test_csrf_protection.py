import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture
def enable_csrf(client):
    # Temporarily enable CSRF protection for the test
    old_value = client.application.config.get('CSRF_ENABLED')
    client.application.config['CSRF_ENABLED'] = True
    yield
    # Restore original value (or remove if not present)
    if old_value is None:
        client.application.config.pop('CSRF_ENABLED', None)
    else:
        client.application.config['CSRF_ENABLED'] = old_value

@patch("backend.blueprints.feeds.fetch_feed")
@patch("backend.blueprints.feeds.process_feed_entries")
def test_csrf_protection(mock_process, mock_fetch, client, enable_csrf):
    """
    Test CSRF protection.
    1. Verify requests without token fail (403).
    2. Verify requests with valid token succeed.
    3. Verify requests with invalid token fail (403).
    """

    # --- Test 1: Missing Token Fails ---
    # Try to create a tab without token
    response = client.post("/api/tabs", json={"name": "CSRF Fail Tab"})
    assert response.status_code == 403
    assert "CSRF token missing" in response.json['error']

    # --- Test 2: Valid Token Succeeds ---

    # Make a GET request to establish a session and get the CSRF cookie
    client.get("/")

    # Retrieve the cookie using the helper method
    cookie_obj = client.get_cookie('csrf_token')
    assert cookie_obj is not None, "CSRF cookie should be set after a request"
    csrf_token = cookie_obj.value

    # Mock for successful feed add
    mock_parsed = MagicMock()
    mock_parsed.feed.get.return_value = "CSRF Success Feed"
    mock_fetch.return_value = mock_parsed
    mock_process.return_value = 0

    headers = {'X-CSRFToken': csrf_token}

    # Create a tab with valid token
    response = client.post("/api/tabs", json={"name": "CSRF Success Tab"}, headers=headers)
    assert response.status_code == 201
    tab_id = response.json['id']

    # Add feed with valid token
    response = client.post("/api/feeds", json={
        "url": "http://example.com/csrf-safe",
        "tab_id": tab_id
    }, headers=headers)

    assert response.status_code == 201
    assert response.json['name'] == "CSRF Success Feed"

    # --- Test 3: Invalid Token Fails ---
    headers_invalid = {'X-CSRFToken': 'wrong_token'}
    response = client.post("/api/tabs", json={"name": "CSRF Invalid Tab"}, headers=headers_invalid)
    assert response.status_code == 403
