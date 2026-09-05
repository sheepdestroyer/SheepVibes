"""Unit tests for E2E conftest live_server fixture logic."""

import configparser
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from tests.e2e.conftest import (
    _get_db_path,
    _get_server_port,
    _get_worker_offset,
    live_server,
)


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


def test_get_worker_offset():
    """Verify _get_worker_offset parses pytest-xdist worker IDs correctly."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_worker_offset() == 0

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "master"}):
        assert _get_worker_offset() == 0

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw0"}):
        assert _get_worker_offset() == 0

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw7"}):
        assert _get_worker_offset() == 7

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gwinvalid"}):
        assert _get_worker_offset() == 0


def test_get_server_port():
    """Verify _get_server_port assigns unique ports per xdist worker."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_server_port() == 5099

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw3"}):
        assert _get_server_port() == 5102

    with patch.dict(os.environ, {"E2E_SERVER_PORT": "6000", "PYTEST_XDIST_WORKER": "gw5"}):
        assert _get_server_port() == 6005


def test_get_db_path(tmp_path):
    """Verify _get_db_path allocates isolated database paths per xdist worker."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_db_path(tmp_path) == tmp_path / "e2e_test.db"

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw2"}):
        assert _get_db_path(tmp_path) == tmp_path / "e2e_test_gw2.db"


def test_live_server_popen_args_with_xdist_worker(mocker):
    """Verify live_server starts subprocess on worker-isolated port and DB path."""
    mocker.patch("tests.e2e.conftest._wait_for_server", return_value=True)
    mock_popen = mocker.patch("subprocess.Popen")
    mock_proc = mock_popen.return_value
    mock_proc.pid = 54321

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw4"}, clear=True):
        gen = live_server.__wrapped__()
        url = next(gen)
        # Port should be 5099 + 4 = 5103
        assert url == "http://127.0.0.1:5103"

        assert mock_popen.called
        _, kwargs = mock_popen.call_args
        env = kwargs.get("env", {})
        assert env.get("PORT") == "5103"
        assert "e2e_test_gw4.db" in env.get("TEST_DATABASE_URI", "")

        mocker.patch("os.killpg")
        mocker.patch("os.getpgid")
        try:
            next(gen)
        except StopIteration:
            pass


def test_pytest_ini_defaults_to_parallel_n_auto():
    """Verify pytest.ini defaults addopts to include -n auto for parallel test runs."""
    project_root = Path(__file__).resolve().parents[2]
    ini_path = project_root / "tests" / "pytest.ini"
    assert ini_path.is_file()

    parser = configparser.ConfigParser()
    parser.read(ini_path)
    addopts = parser.get("pytest", "addopts")
    assert "-n auto" in addopts
    assert "-v" in addopts
    assert "--strict-markers" in addopts


def test_requirements_dev_includes_pytest_xdist():
    """Verify backend/requirements-dev.txt includes pytest-xdist."""
    project_root = Path(__file__).resolve().parents[2]
    req_path = project_root / "backend" / "requirements-dev.txt"
    assert req_path.is_file()
    content = req_path.read_text(encoding="utf-8")
    assert "pytest-xdist" in content
