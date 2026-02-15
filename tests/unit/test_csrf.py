import pytest
from backend.app import app, db

@pytest.fixture
def csrf_client():
    """Fixture that enables CSRF protection for testing."""
    # Save original config
    original_csrf_enabled = app.config.get("WTF_CSRF_ENABLED")
    original_secret = app.config.get("SECRET_KEY")

    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    with app.test_client() as client, app.app_context():
        db.create_all()
        yield client
        db.session.remove()
        db.drop_all()

    # Restore config (though app context is torn down, config persists on app object)
    app.config["WTF_CSRF_ENABLED"] = original_csrf_enabled
    if original_secret:
        app.config["SECRET_KEY"] = original_secret


def test_csrf_missing_token(csrf_client):
    """Test that POST requests fail without CSRF token."""
    response = csrf_client.post("/api/tabs", json={"name": "No Token Tab"})
    assert response.status_code == 400
    # Flask-WTF default error message for missing token
    assert "The CSRF token is missing" in response.get_data(as_text=True)


def test_csrf_valid_token(csrf_client):
    """Test that POST requests succeed with valid CSRF token."""
    # 1. GET request to establish session and get cookie
    response = csrf_client.get("/")
    assert response.status_code == 200

    # Extract CSRF token from cookie
    # get_cookie returns a http.cookiejar.Cookie object in Werkzeug < 3.0 or similar
    # or a TestCookie object. Let's inspect it.
    cookie_obj = csrf_client.get_cookie("csrf_token")
    assert cookie_obj is not None, "csrf_token cookie was not set"
    csrf_token = cookie_obj.value

    # 2. POST request with token in header
    response = csrf_client.post(
        "/api/tabs",
        json={"name": "Valid Token Tab"},
        headers={"X-CSRFToken": csrf_token}
    )
    assert response.status_code == 201
    assert response.json["name"] == "Valid Token Tab"


def test_csrf_invalid_token(csrf_client):
    """Test that POST requests fail with invalid CSRF token."""
    # Establish session
    csrf_client.get("/")

    response = csrf_client.post(
        "/api/tabs",
        json={"name": "Invalid Token Tab"},
        headers={"X-CSRFToken": "fake-token"}
    )
    assert response.status_code == 400
    assert "The CSRF token is invalid" in response.get_data(as_text=True)
