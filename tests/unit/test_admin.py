"""Unit tests for the admin blueprint and management endpoints."""

import pytest
from backend.extensions import db
from backend.models import Feed, FeedItem, Tab, User


@pytest.fixture
def admin_user(client):
    """Creates a dedicated admin user."""
    user = User(username="master_admin", email="admin@example.com", role="admin")
    user.set_password("AdminPass123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def regular_user(client):
    """Creates a regular user with tabs and feeds."""
    user = User(username="regular_bob", email="bob@example.com", role="user")
    user.set_password("BobPass123!")
    db.session.add(user)
    db.session.flush()

    tab = Tab(name="Bob's Tech", order=0, user_id=user.id)
    db.session.add(tab)
    db.session.flush()

    feed = Feed(tab_id=tab.id, name="Bob Feed", url="https://example.com/feed.xml")
    db.session.add(feed)
    db.session.commit()
    return user


def test_admin_endpoints_require_admin_privileges(client, admin_user, regular_user):
    """Verifies that non-admin and unauthenticated users cannot access admin endpoints."""
    # 1. Unauthenticated checks
    client.post("/api/auth/logout")
    for endpoint in [
        ("/api/admin/users", "GET"),
        ("/api/admin/system/stats", "GET"),
        ("/api/admin/backup", "GET"),
    ]:
        resp = client.open(endpoint[0], method=endpoint[1])
        assert resp.status_code == 401

    # 2. Regular user (forbidden 403)
    client.post(
        "/api/auth/login",
        json={"username": "regular_bob", "password": "BobPass123!"},
    )

    resp_users = client.get("/api/admin/users")
    assert resp_users.status_code == 403
    assert "Admin privileges required" in resp_users.json["error"]

    resp_create = client.post(
        "/api/admin/users",
        json={"username": "hacker", "password": "Password123!"},
    )
    assert resp_create.status_code == 403

    resp_update = client.put(
        f"/api/admin/users/{admin_user.id}",
        json={"is_active": False},
    )
    assert resp_update.status_code == 403

    resp_delete = client.delete(f"/api/admin/users/{admin_user.id}")
    assert resp_delete.status_code == 403

    resp_stats = client.get("/api/admin/system/stats")
    assert resp_stats.status_code == 403

    resp_backup = client.get("/api/admin/backup")
    assert resp_backup.status_code == 403


def test_admin_list_users(client, admin_user, regular_user):
    """Verifies admin can list all users with usage statistics."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    resp = client.get("/api/admin/users")
    assert resp.status_code == 200
    data = resp.json
    assert "users" in data
    assert len(data["users"]) >= 2

    # Find regular_bob in the response
    bob_entry = next((u for u in data["users"] if u["username"] == "regular_bob"), None)
    assert bob_entry is not None
    assert bob_entry["role"] == "user"
    assert bob_entry["tabs_count"] == 1
    assert bob_entry["feeds_count"] == 1


def test_admin_create_user(client, admin_user):
    """Verifies admin user creation with validation and default tab creation."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    # 1. Validation: Missing fields
    res = client.post("/api/admin/users", json={"username": "newuser"})
    assert res.status_code == 400

    # 2. Validation: Username invalid characters
    res = client.post(
        "/api/admin/users",
        json={"username": "bad user!", "password": "ValidPassword123!"},
    )
    assert res.status_code == 400

    # 3. Validation: Password too short
    res = client.post(
        "/api/admin/users",
        json={"username": "valid_user", "password": "short"},
    )
    assert res.status_code == 400

    # 4. Validation: Invalid role
    res = client.post(
        "/api/admin/users",
        json={
            "username": "valid_user",
            "password": "ValidPassword123!",
            "role": "superuser",
        },
    )
    assert res.status_code == 400

    # 5. Successful creation
    res = client.post(
        "/api/admin/users",
        json={
            "username": "charlie_new",
            "password": "ValidPassword123!",
            "email": "charlie@example.com",
            "role": "user",
        },
    )
    assert res.status_code == 201
    created_user = res.json["user"]
    assert created_user["username"] == "charlie_new"
    assert created_user["email"] == "charlie@example.com"
    assert created_user["role"] == "user"
    assert created_user["tabs_count"] == 1

    # Verify default tab was created
    tab = Tab.query.filter_by(user_id=created_user["id"]).first()
    assert tab is not None
    assert tab.name == "General"

    # 6. Duplicate username conflict (409)
    res_dup = client.post(
        "/api/admin/users",
        json={
            "username": "CHARLIE_NEW",
            "password": "ValidPassword123!",
        },
    )
    assert res_dup.status_code == 409


def test_admin_update_user(client, admin_user, regular_user):
    """Verifies admin user modification, role toggling, password reset, and self-guards."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    # 1. Update regular user to admin and reset password
    res = client.put(
        f"/api/admin/users/{regular_user.id}",
        json={
            "role": "admin",
            "is_active": True,
            "password": "NewAdminPass123!",
            "email": "bob_new@example.com",
        },
    )
    assert res.status_code == 200
    updated = res.json["user"]
    assert updated["role"] == "admin"
    assert updated["email"] == "bob_new@example.com"

    # Verify new credentials work
    client.post("/api/auth/logout")
    login_res = client.post(
        "/api/auth/login",
        json={"username": "regular_bob", "password": "NewAdminPass123!"},
    )
    assert login_res.status_code == 200

    # 2. Self-guard: Cannot deactivate own account
    client.post("/api/auth/logout")
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )
    self_deact = client.put(
        f"/api/admin/users/{admin_user.id}",
        json={"is_active": False},
    )
    assert self_deact.status_code == 400
    assert "Cannot deactivate your own administrator account" in self_deact.json["error"]

    # 3. Self-guard: Cannot demote own admin account
    self_demote = client.put(
        f"/api/admin/users/{admin_user.id}",
        json={"role": "user"},
    )
    assert self_demote.status_code == 400
    assert "Cannot demote your own administrator account" in self_demote.json["error"]

    # 4. Not found 404
    not_found = client.put("/api/admin/users/99999", json={"role": "user"})
    assert not_found.status_code == 404


def test_admin_delete_user(client, admin_user, regular_user):
    """Verifies admin user deletion with cascade and self-deletion prevention."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    # 1. Self-guard: Cannot delete own account
    self_del = client.delete(f"/api/admin/users/{admin_user.id}")
    assert self_del.status_code == 400
    assert "Cannot delete your own administrator account" in self_del.json["error"]

    # 2. Delete regular user
    bob_tab_id = Tab.query.filter_by(user_id=regular_user.id).first().id
    del_res = client.delete(f"/api/admin/users/{regular_user.id}")
    assert del_res.status_code == 200
    assert "deleted successfully" in del_res.json["message"]

    # Verify user and cascaded tabs are gone
    assert db.session.get(User, regular_user.id) is None
    assert db.session.get(Tab, bob_tab_id) is None
    assert Feed.query.filter_by(tab_id=bob_tab_id).first() is None

    # 3. Delete non-existent user (404)
    del_404 = client.delete("/api/admin/users/99999")
    assert del_404.status_code == 404


def test_admin_system_stats(client, admin_user):
    """Verifies system diagnostics and usage stats retrieval."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    resp = client.get("/api/admin/system/stats")
    assert resp.status_code == 200
    stats = resp.json["stats"]

    assert "users_count" in stats
    assert "tabs_count" in stats
    assert "feeds_count" in stats
    assert "items_count" in stats
    assert "unread_items_count" in stats
    assert "db_size_bytes" in stats
    assert "cache_type" in stats
    assert "cache_status" in stats
    assert "python_version" in stats
    assert "server_time" in stats


def test_admin_backup_download(client, admin_user):
    """Verifies admin SQLite database backup point-in-time snapshot download."""
    client.post(
        "/api/auth/login",
        json={"username": "master_admin", "password": "AdminPass123!"},
    )

    resp = client.get("/api/admin/backup")
    assert resp.status_code == 200
    assert resp.mimetype == "application/x-sqlite3"
    assert "sheepvibes_backup_" in resp.headers.get("Content-Disposition", "")
    assert len(resp.data) > 0
