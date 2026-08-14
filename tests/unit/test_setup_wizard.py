"""Unit tests for the first-run onboarding setup wizard and auth status."""

from backend.models import Tab, User


def test_auth_status_setup_required_when_no_users(unauth_client):
    """Verifies that /api/auth/status indicates setup_required when no users exist."""
    res = unauth_client.get("/api/auth/status")
    assert res.status_code == 200
    assert res.json["setup_required"] is True
    assert res.json["authenticated"] is False
    assert res.json["user"] is None


def test_initial_setup_flow_and_subsequent_rejection(unauth_client):
    """Verifies creating master administrator via /api/auth/setup and subsequent 403 rejection."""
    # 1. Validation error: Missing fields
    res = unauth_client.post("/api/auth/setup", json={"username": "root"})
    assert res.status_code == 400

    # 2. Validation error: Invalid username
    res = unauth_client.post(
        "/api/auth/setup",
        json={"username": "ab", "password": "Password123!"},
    )
    assert res.status_code == 400

    # 3. Validation error: Short password
    res = unauth_client.post(
        "/api/auth/setup",
        json={"username": "master_admin", "password": "123"},
    )
    assert res.status_code == 400

    # 4. Successful master administrator setup
    res = unauth_client.post(
        "/api/auth/setup",
        json={
            "username": "super_admin",
            "password": "MasterAdminPass123!",
            "email": "admin@example.com",
        },
    )
    assert res.status_code == 201
    user_data = res.json["user"]
    assert user_data["username"] == "super_admin"
    assert user_data["email"] == "admin@example.com"
    assert user_data["role"] == "admin"

    # Verify default tab was created
    tab = Tab.query.filter_by(user_id=user_data["id"]).first()
    assert tab is not None
    assert tab.name == "General"

    # 5. Verify /api/auth/status reflects setup_required = False and authenticated = True
    status_res = unauth_client.get("/api/auth/status")
    assert status_res.status_code == 200
    assert status_res.json["setup_required"] is False
    assert status_res.json["authenticated"] is True
    assert status_res.json["user"]["username"] == "super_admin"

    # 6. Attempt second setup call (must be rejected with 403 Forbidden)
    res_repeat = unauth_client.post(
        "/api/auth/setup",
        json={
            "username": "another_admin",
            "password": "MasterAdminPass123!",
        },
    )
    assert res_repeat.status_code == 403
    assert "Setup has already been completed" in res_repeat.json["error"]
