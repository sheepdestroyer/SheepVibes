import pytest
import socket
from unittest.mock import MagicMock

@pytest.fixture
def mock_dns(mocker):
    """Mock socket.getaddrinfo to prevent DNS resolution errors during tests."""
    mock_getaddrinfo = mocker.patch('backend.feed_service.socket.getaddrinfo')
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))
    ]
    return mock_getaddrinfo
