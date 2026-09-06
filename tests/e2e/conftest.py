"""E2E test fixtures for SheepVibes Playwright tests.

Provides automatic Flask server lifecycle management, viewport configuration,
and configurable base URL support. Modeled after the AI-DIVORCE project's
proven headless Chromium setup.

Usage:
    E2E tests automatically get a running Flask server via the ``live_server``
    session fixture. The server is started once per test session and torn down
    after all e2e tests complete.

    Set TEST_BASE_URL to override the default (http://127.0.0.1:5099).
    The port 5099 is chosen to avoid conflicts with dev servers on 5000.

Environment Variables:
    TEST_BASE_URL: Override the base URL for e2e tests (default: http://127.0.0.1:5099)
    E2E_SERVER_PORT: Override the Flask server port (default: 5099)
    E2E_SERVER_TIMEOUT: Seconds to wait for server startup (default: 15)
"""

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

E2E_SERVER_PORT = int(os.environ.get("E2E_SERVER_PORT", "5099"))
E2E_SERVER_TIMEOUT = int(os.environ.get("E2E_SERVER_TIMEOUT", "30"))
E2E_BASE_URL = os.environ.get(
    "TEST_BASE_URL", f"http://127.0.0.1:{E2E_SERVER_PORT}"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_worker_offset() -> int:
    """Return a numeric port offset based on the pytest-xdist worker ID if present."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker.startswith("gw"):
        try:
            return int(worker[2:])
        except ValueError:
            return 0
    return 0


def _get_server_port() -> int:
    """Return the server port for this worker process."""
    env_port = os.environ.get("E2E_SERVER_PORT") or os.environ.get("PORT")
    if env_port:
        try:
            base_port = int(env_port)
        except ValueError:
            base_port = E2E_SERVER_PORT
    else:
        base_port = E2E_SERVER_PORT
    return base_port + _get_worker_offset()


def _get_db_path(data_dir: Path) -> Path:
    """Return an isolated database path for this worker process."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker:
        return data_dir / f"e2e_test_{worker}.db"
    return data_dir / "e2e_test.db"


def _get_log_path(data_dir: Path) -> Path:
    """Return an isolated server log path for this worker process."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker:
        return data_dir / f"e2e_server_{worker}.log"
    return data_dir / "e2e_server.log"


def _read_server_logs(log_path: Path | None) -> str:
    """Read captured server logs if available."""
    if log_path is not None and log_path.exists():
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace").strip()
            return content if content else "(no server output captured)"
        except OSError as exc:
            return f"(failed to read server logs: {exc})"
    return "(no server log file found)"


def _wait_for_server(
    host: str,
    port: int,
    timeout: int,
    proc: subprocess.Popen | None = None,
    log_path: Path | None = None,
) -> bool:
    """Poll until the server is accepting TCP connections or timeout expires.

    Periodically checks if the subprocess terminated prematurely. If so, aborts
    polling immediately and fails with the exit code and captured server logs.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            logs = _read_server_logs(log_path)
            pytest.fail(
                f"Flask server terminated prematurely with exit code {proc.poll()} "
                f"on port {port}.\nServer Output:\n{logs}".rstrip()
            )
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def live_server():
    """Start a Flask development server for the e2e test session.

    The server runs in a subprocess with TESTING=true and an isolated
    SQLite database. It is automatically terminated after the session.
    If TEST_BASE_URL is set in os.environ, yield that URL directly.
    """
    if "TEST_BASE_URL" in os.environ:
        yield os.environ["TEST_BASE_URL"]
        return

    project_root = Path(__file__).resolve().parents[2]  # tests/e2e -> project root
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    server_port = _get_server_port()
    server_base_url = f"http://127.0.0.1:{server_port}"
    e2e_db_path = _get_db_path(data_dir)
    server_log_path = _get_log_path(data_dir)

    if e2e_db_path.exists():
        try:
            e2e_db_path.unlink()
        except OSError:
            pass

    if server_log_path.exists():
        try:
            server_log_path.unlink()
        except OSError:
            pass

    # Use the same Python interpreter that is running pytest
    python = sys.executable

    env = os.environ.copy()
    env.update({
        "TESTING": "true",
        "FLASK_DEBUG": "0",
        "PYTHONUNBUFFERED": "1",
        # Use a non-default port to avoid conflicts with dev servers
        "PORT": str(server_port),
        "TEST_DATABASE_URI": f"sqlite:///{e2e_db_path}",
    })

    log_file = open(server_log_path, "w+", encoding="utf-8")
    proc = None
    started = False
    try:
        # Start Flask via `python -m backend.app` from the project root
        proc = subprocess.Popen(
            [python, "-m", "backend.app"],
            cwd=str(project_root),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        # Wait for server to accept connections
        if not _wait_for_server(
            "127.0.0.1",
            server_port,
            E2E_SERVER_TIMEOUT,
            proc=proc,
            log_path=server_log_path,
        ):
            logs = _read_server_logs(server_log_path)
            pytest.fail(
                f"Flask server failed to start on port {server_port} "
                f"within {E2E_SERVER_TIMEOUT}s.\n"
                f"Server Output:\n{logs}".rstrip()
            )

        started = True
        yield server_base_url
    finally:
        # Teardown: kill the entire process group
        if proc is not None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                else:
                    proc.terminate()
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    if hasattr(os, "killpg"):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
        try:
            log_file.flush()
        except (ValueError, OSError):
            pass
        log_file.close()
        if e2e_db_path.exists():
            try:
                e2e_db_path.unlink()
            except OSError:
                pass
        if started and server_log_path.exists():
            try:
                server_log_path.unlink()
            except OSError:
                pass


@pytest.fixture(scope="function", autouse=True)
def configure_page_viewport(page: Page):
    """Configure browser viewport to 1920x1080 for all E2E tests.

    Matches the AI-DIVORCE project's viewport configuration for consistent
    rendering of the full desktop layout.
    """
    page.set_viewport_size({"width": 1920, "height": 1080})
    yield page


@pytest.fixture(scope="function", autouse=True)
def default_auth_state(page: Page, live_server: str):
    """By default in E2E tests, establish an authenticated admin session on the live server."""
    page.context.request.post(
        f"{live_server}/api/auth/login",
        data={"username": "admin", "password": "DefaultPass123!"},
        headers={"Content-Type": "application/json"},
    )
    yield
