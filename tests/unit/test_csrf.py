import pytest

from backend.app import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, app


def test_csrf_protection_flow(client):
    """Test the full CSRF protection flow."""
    # Enable CSRF for this test (it's disabled by default in conftest)
    app.config["CSRF_ENABLED"] = True

    # 1. Initial GET request to obtain the CSRF cookie
    response = client.get("/api/tabs")
    assert response.status_code == 200

    # Verify the cookie is set
    csrf_cookie = client.get_cookie(CSRF_COOKIE_NAME)

    assert csrf_cookie is not None, "CSRF cookie was not set on GET request"
    token = csrf_cookie.value
    assert token, "CSRF token value is empty"

    # 2. Test POST without headers/cookies (should fail)
    # We create a new client or clear cookies to simulate missing cookie?
    # But client maintains jar.
    # Let's try sending a request without the header first.
    response = client.post("/api/tabs", json={"name": "Should Fail 1"})
    assert response.status_code == 403
    assert b"CSRF token missing or invalid" in response.data

    # 3. Test POST with cookie but missing header (should fail)
    response = client.post("/api/tabs", json={"name": "Should Fail 2"})
    assert response.status_code == 403

    # 4. Test POST with header but mismatching token (should fail)
    response = client.post(
        "/api/tabs",
        json={"name": "Should Fail 3"},
        headers={CSRF_HEADER_NAME: "wrong_token"},
    )
    assert response.status_code == 403

    # 5. Test POST with matching cookie and header (should succeed)
    # Note: We use a unique name to avoid conflict if DB is not reset
    response = client.post(
        "/api/tabs", json={"name": "CSRF Test Tab"}, headers={CSRF_HEADER_NAME: token}
    )
    # Expect 201 Created or 200 OK
    assert response.status_code in [
        200,
        201,
    ], f"Request failed with status {response.status_code}: {response.data}"

    # Reset config (though fixture teardown handles app context, config might persist in memory if not careful)
    app.config["CSRF_ENABLED"] = False
