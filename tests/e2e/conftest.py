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
E2E_SERVER_TIMEOUT = int(os.environ.get("E2E_SERVER_TIMEOUT", "15"))
E2E_BASE_URL = os.environ.get(
    "TEST_BASE_URL", f"http://127.0.0.1:{E2E_SERVER_PORT}"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_server(host: str, port: int, timeout: int) -> bool:
    """Poll until the server is accepting TCP connections or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
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
    e2e_db_path = project_root / "data" / "e2e_test.db"
    if e2e_db_path.exists():
        try:
            e2e_db_path.unlink()
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
        "PORT": str(E2E_SERVER_PORT),
        "TEST_DATABASE_URI": f"sqlite:///{e2e_db_path}",
    })

    # Start Flask via `python -m backend.app` from the project root
    proc = subprocess.Popen(
        [python, "-m", "backend.app"],
        cwd=str(project_root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Wait for server to accept connections
    if not _wait_for_server("127.0.0.1", E2E_SERVER_PORT, E2E_SERVER_TIMEOUT):
        proc.terminate()
        pytest.fail(
            f"Flask server failed to start on port {E2E_SERVER_PORT} "
            f"within {E2E_SERVER_TIMEOUT}s."
        )

    yield E2E_BASE_URL

    # Teardown: kill the entire process group
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
    finally:
        if e2e_db_path.exists():
            try:
                e2e_db_path.unlink()
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
