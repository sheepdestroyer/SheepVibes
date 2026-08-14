"""Unit tests for user model, authentication utilities, and auth blueprint endpoints."""

import pytest
from backend.auth import admin_required, get_current_user, login_required, login_user, logout_user
from backend.extensions import db
from backend.models import Tab, User


def test_user_password_hashing():
    """Verifies that passwords are securely hashed and checked correctly."""
    user = User(username="testuser", email="test@example.com")
    user.set_password("MySecurePass123!")

    assert user.password_hash is not None
    assert user.password_hash != "MySecurePass123!"
    assert user.check_password("MySecurePass123!") is True
    assert user.check_password("WrongPassword") is False
    assert user.check_password("") is False


def test_user_is_admin_and_to_dict():
    """Verifies is_admin property and dictionary serialization."""
    admin = User(username="adminuser", role="admin")
    regular = User(username="reguser", role="user")

    assert admin.is_admin is True
    assert regular.is_admin is False

    admin_dict = admin.to_dict()
    assert admin_dict["username"] == "adminuser"
    assert admin_dict["role"] == "admin"
    assert admin_dict["is_admin"] is True
    assert admin_dict["is_active"] is True


def test_user_tab_relationship_and_cascade(client):
    """Verifies Tab user_id relationship and cascade deletion."""
    user = User(username="tabowner", password_hash="hash")
    db.session.add(user)
    db.session.commit()

    tab = Tab(name="User Tab", user_id=user.id)
    db.session.add(tab)
    db.session.commit()

    assert tab.user_id == user.id
    assert len(user.tabs) == 1
    assert user.tabs[0].name == "User Tab"

    # Deleting the user should cascade delete their tabs
    db.session.delete(user)
    db.session.commit()
    assert Tab.query.filter_by(name="User Tab").first() is None


def test_api_login_success(client):
    """Verifies successful user login returns 200 and session is established."""
    user = User(username="john_doe", email="john@example.com", role="user")
    user.set_password("CorrectPass123")
    db.session.add(user)
    db.session.commit()

    # Case-insensitive login
    response = client.post(
        "/api/auth/login",
        json={"username": "John_Doe", "password": "CorrectPass123"},
    )
    assert response.status_code == 200
    data = response.json
    assert data["message"] == "Login successful"
    assert data["user"]["username"] == "john_doe"
    assert data["user"]["is_admin"] is False

    # Check /api/auth/me returns authenticated state
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    me_data = me_resp.json
    assert me_data["authenticated"] is True
    assert me_data["user"]["username"] == "john_doe"


def test_api_login_failures(client):
    """Verifies invalid login credentials and missing parameters return appropriate errors."""
    user = User(username="active_user", role="user")
    user.set_password("ValidPassword123")
    deactivated_user = User(username="inactive_user", role="user", is_active=False)
    deactivated_user.set_password("ValidPassword123")
    db.session.add_all([user, deactivated_user])
    db.session.commit()

    # Missing fields
    res_missing = client.post("/api/auth/login", json={"username": "active_user"})
    assert res_missing.status_code == 400

    # Wrong password
    res_wrong = client.post(
        "/api/auth/login",
        json={"username": "active_user", "password": "WrongPassword"},
    )
    assert res_wrong.status_code == 401
    assert "Invalid username or password" in res_wrong.json["error"]

    # Non-existent username
    res_not_found = client.post(
        "/api/auth/login",
        json={"username": "non_existent", "password": "AnyPassword"},
    )
    assert res_not_found.status_code == 401

    # Deactivated account
    res_deactivated = client.post(
        "/api/auth/login",
        json={"username": "inactive_user", "password": "ValidPassword123"},
    )
    assert res_deactivated.status_code == 403
    assert "Account is deactivated" in res_deactivated.json["error"]


def test_api_logout(client):
    """Verifies logout clears the session."""
    user = User(username="logout_user", role="user")
    user.set_password("Password123")
    db.session.add(user)
    db.session.commit()

    client.post("/api/auth/login", json={"username": "logout_user", "password": "Password123"})
    me_before = client.get("/api/auth/me").json
    assert me_before["authenticated"] is True

    logout_resp = client.post("/api/auth/logout")
    assert logout_resp.status_code == 200

    me_after = client.get("/api/auth/me").json
    assert me_after["authenticated"] is False
    assert me_after["user"] is None


def test_api_change_password(client):
    """Verifies authenticated user password changes."""
    user = User(username="pwd_user", role="user")
    user.set_password("OldPass123")
    db.session.add(user)
    db.session.commit()

    # Unauthenticated change password attempt
    unauth_resp = client.put(
        "/api/auth/password",
        json={"current_password": "OldPass123", "new_password": "NewSecretPass456"},
    )
    assert unauth_resp.status_code == 401

    # Log in
    client.post("/api/auth/login", json={"username": "pwd_user", "password": "OldPass123"})

    # Incorrect current password
    wrong_curr = client.put(
        "/api/auth/password",
        json={"current_password": "WrongOldPass", "new_password": "NewSecretPass456"},
    )
    assert wrong_curr.status_code == 401

    # Password too short
    too_short = client.put(
        "/api/auth/password",
        json={"current_password": "OldPass123", "new_password": "short"},
    )
    assert too_short.status_code == 400

    # Successful password update
    success_resp = client.put(
        "/api/auth/password",
        json={"current_password": "OldPass123", "new_password": "NewSecretPass456"},
    )
    assert success_resp.status_code == 200

    # Verify login with new password
    client.post("/api/auth/logout")
    login_new = client.post(
        "/api/auth/login",
        json={"username": "pwd_user", "password": "NewSecretPass456"},
    )
    assert login_new.status_code == 200


def test_login_and_admin_required_decorators(client):
    """Verifies that @login_required and @admin_required properly protect endpoints."""
    from flask import jsonify

    @login_required
    def protected_view():
        return jsonify({"success": True}), 200

    @admin_required
    def admin_view():
        return jsonify({"admin_success": True}), 200

    regular_user = User(username="regular", role="user")
    regular_user.set_password("pass123")
    admin_user = User(username="admin_guy", role="admin")
    admin_user.set_password("pass123")
    db.session.add_all([regular_user, admin_user])
    db.session.commit()

    # 1. Unauthenticated requests
    with client.application.test_request_context():
        resp, code = protected_view()
        assert code == 401
        admin_resp, admin_code = admin_view()
        assert admin_code == 401

    # 2. Authenticated regular user
    with client.application.test_request_context():
        login_user(regular_user)
        resp, code = protected_view()
        assert code == 200
        admin_resp, admin_code = admin_view()
        assert admin_code == 403

    # 3. Authenticated admin user
    with client.application.test_request_context():
        login_user(admin_user)
        resp, code = protected_view()
        assert code == 200
        admin_resp, admin_code = admin_view()
        assert admin_code == 200
