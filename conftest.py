import os
import socket

import pytest

from backend.app import app, db

os.environ["TESTING"] = "true"

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

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()
