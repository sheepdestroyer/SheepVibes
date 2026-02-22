def test_register_and_login(client):
    # Use unique username
    username = "newuser_reg"
    # Register
    res = client.post(
        "/api/auth/register", json={"username": username, "password": "password123"}
    )
    assert res.status_code == 201

    # Login
    res = client.post(
        "/api/auth/login", json={"username": username, "password": "password123"}
    )
    assert res.status_code == 200
    assert res.get_json()["username"] == username

    # Me
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    assert res.get_json()["username"] == username


def test_multiuser_isolation(client):
    # testuser already exists from conftest

    # Login as u1 (already logged in as testuser by default, but let's be explicit)
    client.post(
        "/api/auth/login", json={"username": "testuser", "password": "password"}
    )
    client.post("/api/tabs", json={"name": "Tab U1"})

    # Logout
    client.post("/api/auth/logout")

    # Register and Login as u2
    client.post("/api/auth/register",
                json={"username": "u2", "password": "p2"})
    client.post("/api/auth/login", json={"username": "u2", "password": "p2"})

    res = client.get("/api/tabs")
    tabs = res.get_json()
    assert len(tabs) == 0  # u2 shouldn't see testuser's tabs

    client.post("/api/tabs", json={"name": "Tab U2"})
    res = client.get("/api/tabs")
    assert len(res.get_json()) == 1
    assert res.get_json()[0]["name"] == "Tab U2"


def test_admin_access(client):
    # testuser is admin from conftest
    client.post(
        "/api/auth/login", json={"username": "testuser", "password": "password"}
    )

    res = client.get("/api/admin/users")
    assert res.status_code == 200

    # Create non-admin user
    client.post("/api/auth/logout")
    client.post(
        "/api/auth/register", json={"username": "regular_user", "password": "p2"}
    )
    client.post("/api/auth/login",
                json={"username": "regular_user", "password": "p2"})

    res = client.get("/api/admin/users")
    assert res.status_code == 403  # Forbidden
