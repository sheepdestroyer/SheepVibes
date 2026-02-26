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
    # Using specific exception instead of assert for production code safety, though this is test code.
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
    app.config["CSRF_ENABLED"] = False  # Disable CSRF for tests by default
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    with app.test_client() as client, app.app_context():
        db.create_all()
        yield client
        db.session.remove()
        db.drop_all()
