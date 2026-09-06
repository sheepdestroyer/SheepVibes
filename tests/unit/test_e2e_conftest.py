"""Unit tests for E2E conftest live_server fixture logic."""

import configparser
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.e2e.conftest import (
    _get_db_path,
    _get_log_path,
    _get_server_port,
    _get_worker_offset,
    _read_server_logs,
    _wait_for_server,
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
    """Verify live_server subprocess arguments include start_new_session and log capture streams."""
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
        assert kwargs.get("stdout") is not None
        assert kwargs.get("stdout") != subprocess.DEVNULL
        assert kwargs.get("stderr") == subprocess.STDOUT

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


def test_get_server_port_with_port_env_var():
    """Verify _get_server_port respects PORT env var and precedence rules."""
    with patch.dict(os.environ, {"PORT": "7000"}, clear=True):
        assert _get_server_port() == 7000

    with patch.dict(os.environ, {"PORT": "7000", "PYTEST_XDIST_WORKER": "gw2"}, clear=True):
        assert _get_server_port() == 7002

    # E2E_SERVER_PORT takes precedence over PORT
    with patch.dict(os.environ, {"E2E_SERVER_PORT": "8000", "PORT": "7000"}, clear=True):
        assert _get_server_port() == 8000

    # Invalid port string falls back to default
    with patch.dict(os.environ, {"PORT": "invalid"}, clear=True):
        assert _get_server_port() == 5099


def test_get_db_path(tmp_path):
    """Verify _get_db_path allocates isolated database paths per xdist worker."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_db_path(tmp_path) == tmp_path / "e2e_test.db"

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw2"}):
        assert _get_db_path(tmp_path) == tmp_path / "e2e_test_gw2.db"


def test_get_log_path(tmp_path):
    """Verify _get_log_path allocates isolated server log paths per xdist worker."""
    with patch.dict(os.environ, {}, clear=True):
        assert _get_log_path(tmp_path) == tmp_path / "e2e_server.log"

    with patch.dict(os.environ, {"PYTEST_XDIST_WORKER": "gw1"}):
        assert _get_log_path(tmp_path) == tmp_path / "e2e_server_gw1.log"


def test_read_server_logs(tmp_path):
    """Verify _read_server_logs handles existing, missing, and empty log files gracefully."""
    # Missing file
    missing = tmp_path / "nonexistent.log"
    assert "no server output captured" in _read_server_logs(missing) or "no server" in _read_server_logs(missing)

    # Empty file
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert _read_server_logs(empty) == "(no server output captured)"

    # File with content
    content_file = tmp_path / "server.log"
    content_file.write_text("Starting Flask app on port 5099...", encoding="utf-8")
    assert _read_server_logs(content_file) == "Starting Flask app on port 5099..."

    # None path
    assert _read_server_logs(None) == "(no server log file found)"


def test_wait_for_server_fast_abort_on_premature_exit(tmp_path):
    """Verify _wait_for_server fast-aborts and reports exit code and stderr logs when subprocess exits early."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 1
    log_path = tmp_path / "e2e_server.log"
    log_path.write_text(
        "Traceback (most recent call last):\n"
        "  File \"backend/app.py\", line 454, in <module>\n"
        "OSError: [Errno 98] Address already in use: '127.0.0.1:5099'",
        encoding="utf-8",
    )

    start = time.monotonic()
    with pytest.raises(pytest.fail.Exception) as exc_info:
        _wait_for_server("127.0.0.1", 5099, timeout=15, proc=mock_proc, log_path=log_path)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0  # Fast abort, does not wait 15 seconds
    msg = str(exc_info.value)
    assert "terminated prematurely with exit code 1" in msg
    assert "port 5099" in msg
    assert "Address already in use" in msg


def test_wait_for_server_timeout_alive_process(mocker):
    """Verify _wait_for_server returns False if timeout expires while process is still alive."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # Process still running
    mocker.patch("socket.create_connection", side_effect=OSError("Connection refused"))

    res = _wait_for_server("127.0.0.1", 5099, timeout=0.1, proc=mock_proc)
    assert res is False


def test_live_server_startup_failure_premature_exit(mocker, tmp_path):
    """Verify live_server fixture fails with exit code and server logs when server crashes."""
    mock_proc = mocker.MagicMock()
    mock_proc.pid = 9876
    mock_proc.poll.return_value = 1

    def fake_popen(*args, **kwargs):
        if "stdout" in kwargs and hasattr(kwargs["stdout"], "write"):
            kwargs["stdout"].write("ModuleNotFoundError: No module named 'invalid_dependency'\n")
            kwargs["stdout"].flush()
        return mock_proc

    mocker.patch("subprocess.Popen", side_effect=fake_popen)
    mocker.patch("os.killpg")
    mocker.patch("os.getpgid")

    log_path = tmp_path / "e2e_server.log"
    mocker.patch("tests.e2e.conftest._get_log_path", return_value=log_path)

    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("TEST_BASE_URL", None)
        gen = live_server.__wrapped__()
        with pytest.raises(pytest.fail.Exception) as exc_info:
            try:
                next(gen)
            except StopIteration:
                pass

        msg = str(exc_info.value)
        assert "terminated prematurely with exit code 1" in msg
        assert "ModuleNotFoundError: No module named 'invalid_dependency'" in msg


def test_live_server_startup_failure_timeout(mocker, tmp_path):
    """Verify live_server fixture fails with port, timeout, and logs when server startup hangs."""
    mock_proc = mocker.MagicMock()
    mock_proc.pid = 9877
    mock_proc.poll.return_value = None

    def fake_popen(*args, **kwargs):
        if "stdout" in kwargs and hasattr(kwargs["stdout"], "write"):
            kwargs["stdout"].write("Starting Flask app on port 5099...\nWaiting for DB lock...\n")
            kwargs["stdout"].flush()
        return mock_proc

    mocker.patch("subprocess.Popen", side_effect=fake_popen)
    mocker.patch("tests.e2e.conftest._wait_for_server", return_value=False)
    mocker.patch("os.killpg")
    mocker.patch("os.getpgid")

    log_path = tmp_path / "e2e_server.log"
    mocker.patch("tests.e2e.conftest._get_log_path", return_value=log_path)

    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("TEST_BASE_URL", None)
        gen = live_server.__wrapped__()
        with pytest.raises(pytest.fail.Exception) as exc_info:
            try:
                next(gen)
            except StopIteration:
                pass

        msg = str(exc_info.value)
        assert "failed to start on port 5099 within" in msg
        assert "Waiting for DB lock..." in msg


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
