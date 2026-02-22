import pytest

from backend.models import Feed, Subscription, Tab, User


def test_register_and_login(client):
    # Register
    res = client.post(
        "/api/auth/register", json={"username": "testuser", "password": "password123"}
    )
    assert res.status_code == 201

    # Login
    res = client.post(
        "/api/auth/login", json={"username": "testuser", "password": "password123"}
    )
    assert res.status_code == 200
    assert res.get_json()["username"] == "testuser"

    # Me
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    assert res.get_json()["username"] == "testuser"


def test_multiuser_isolation(client):
    # Create two users
    client.post("/api/auth/register",
                json={"username": "u1", "password": "p1"})
    client.post("/api/auth/register",
                json={"username": "u2", "password": "p2"})

    # Login as u1
    client.post("/api/auth/login", json={"username": "u1", "password": "p1"})
    client.post("/api/tabs", json={"name": "Tab U1"})

    # Logout u1
    client.post("/api/auth/logout")

    # Login as u2
    client.post("/api/auth/login", json={"username": "u2", "password": "p2"})
    res = client.get("/api/tabs")
    tabs = res.get_json()
    assert len(tabs) == 0  # u2 shouldn't see u1's tabs

    client.post("/api/tabs", json={"name": "Tab U2"})
    res = client.get("/api/tabs")
    assert len(res.get_json()) == 1
    assert res.get_json()[0]["name"] == "Tab U2"


def test_admin_access(client):
    # First user is admin
    client.post("/api/auth/register",
                json={"username": "admin", "password": "p1"})
    client.post("/api/auth/login",
                json={"username": "admin", "password": "p1"})

    res = client.get("/api/admin/users")
    assert res.status_code == 200
    assert len(res.get_json()) == 1

    # Second user is NOT admin
    client.post("/api/auth/logout")
    client.post("/api/auth/register",
                json={"username": "user", "password": "p2"})
    client.post("/api/auth/login", json={"username": "user", "password": "p2"})

    res = client.get("/api/admin/users")
    assert res.status_code == 403  # Forbidden
