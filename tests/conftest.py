import os
import socket
from pathlib import Path

import pytest

from backend.app import app, db

os.environ["TESTING"] = "true"


@pytest.fixture(scope="session", name="tests_root")
def fixture_tests_root():
    """Return the root path of the tests directory."""
    return Path(__file__).parent.resolve()


@pytest.fixture
def opml_file_path(tests_root):
    """Return the path to the test OPML file, ensuring it exists."""
    path = tests_root.joinpath("test_feeds.opml")
    if not path.is_file():
        raise FileNotFoundError(f"Test data file not found at: {path}")
    return path


EXAMPLE_COM_IP = "93.184.216.34"


@pytest.fixture
def mock_dns(mocker):
    """Mock socket.getaddrinfo to prevent DNS resolution errors during tests."""
    mock_getaddrinfo = mocker.patch("backend.feed_service.socket.getaddrinfo")
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (EXAMPLE_COM_IP, 80))
    ]
    return mock_getaddrinfo


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "test-secret"
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["CACHE_TYPE"] = "SimpleCache"

    from backend.app import cache

    with app.test_client() as client, app.app_context():
        db.create_all()
        cache.clear()
        # Create a default admin user and log them in
        from backend.extensions import bcrypt
        from backend.models import User

        username = "testuser"
        password = os.environ.get("TEST_PASSWORD", "password")
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username,
                    password_hash=password_hash, is_admin=True)
        db.session.add(user)
        db.session.commit()

        client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        yield client
        db.session.remove()
        db.drop_all()


@pytest.fixture
def auth_client(client):
    """Alias for client since it's already authenticated."""
    return client
