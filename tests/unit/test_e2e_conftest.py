"""Unit tests for E2E conftest live_server fixture logic."""

import os
import subprocess
from unittest.mock import patch

from tests.e2e.conftest import live_server


def test_live_server_uses_existing_test_base_url():
    """Verify live_server yields TEST_BASE_URL when set, without launching server subprocess."""
    custom_url = "http://custom-test-server:8080"
    with patch.dict(os.environ, {"TEST_BASE_URL": custom_url}):
        gen = live_server.__wrapped__()
        url = next(gen)
        assert url == custom_url
        # Clean exit generator
        try:
            next(gen)
        except StopIteration:
            pass


def test_live_server_popen_args(mocker):
    """Verify live_server subprocess arguments include start_new_session and DEVNULL streams."""
    mocker.patch("tests.e2e.conftest._wait_for_server", return_value=True)
    mock_popen = mocker.patch("subprocess.Popen")
    mock_proc = mock_popen.return_value
    mock_proc.pid = 12345

    with patch.dict(os.environ, {}, clear=True):
        # Ensure TEST_BASE_URL is not set
        os.environ.pop("TEST_BASE_URL", None)
        gen = live_server.__wrapped__()
        url = next(gen)
        assert url == "http://127.0.0.1:5099"

        # Verify subprocess.Popen call parameters
        assert mock_popen.called
        _, kwargs = mock_popen.call_args
        assert kwargs.get("start_new_session") is True
        assert kwargs.get("stdout") == subprocess.DEVNULL
        assert kwargs.get("stderr") == subprocess.DEVNULL

        mocker.patch("os.killpg")
        mocker.patch("os.getpgid")
        try:
            next(gen)
        except StopIteration:
            pass
