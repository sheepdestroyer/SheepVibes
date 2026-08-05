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
    """
    project_root = Path(__file__).resolve().parents[2]  # tests/e2e -> project root

    # Use the same Python interpreter that is running pytest
    python = sys.executable

    env = os.environ.copy()
    env.update({
        "TESTING": "true",
        "FLASK_DEBUG": "0",
        "PYTHONUNBUFFERED": "1",
        # Use a non-default port to avoid conflicts with dev servers
        "PORT": str(E2E_SERVER_PORT),
    })

    # Start Flask via `python -m backend.app` from the project root
    proc = subprocess.Popen(
        [python, "-m", "backend.app"],
        cwd=str(project_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        # Use process group so we can kill the entire tree
        preexec_fn=os.setsid,
    )

    # Wait for server to accept connections
    if not _wait_for_server("127.0.0.1", E2E_SERVER_PORT, E2E_SERVER_TIMEOUT):
        # Capture output for debugging
        proc.terminate()
        stdout, _ = proc.communicate(timeout=5)
        output = stdout.decode("utf-8", errors="replace") if stdout else "(no output)"
        pytest.fail(
            f"Flask server failed to start on port {E2E_SERVER_PORT} "
            f"within {E2E_SERVER_TIMEOUT}s.\nServer output:\n{output}"
        )

    yield E2E_BASE_URL

    # Teardown: kill the entire process group
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.fixture(scope="function", autouse=True)
def configure_page_viewport(page: Page):
    """Configure browser viewport to 1920x1080 for all E2E tests.

    Matches the AI-DIVORCE project's viewport configuration for consistent
    rendering of the full desktop layout.
    """
    page.set_viewport_size({"width": 1920, "height": 1080})
    yield page
