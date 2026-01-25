"""
Backend-specific pytest configuration.
This file is discovered by pytest when running from the backend directory.
"""
import os
os.environ['TESTING'] = 'true'

import pytest
import socket

# Import the app after setting the environment variable
from backend.app import app, db

EXAMPLE_COM_IP = "93.184.216.34"


@pytest.fixture
def mock_dns(mocker):
    """Mock socket.getaddrinfo to prevent DNS resolution errors during tests."""
    mock_getaddrinfo = mocker.patch('backend.feed_service.socket.getaddrinfo')
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', (EXAMPLE_COM_IP, 80))
    ]
    return mock_getaddrinfo


@pytest.fixture
def client():
    """Provides a test client for making requests to the Flask app."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    with app.test_client() as test_client:
        with app.app_context():
            db.create_all()
            yield test_client
            db.session.remove()
            db.drop_all()
