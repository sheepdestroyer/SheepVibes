# Testing Guide for SheepVibes

SheepVibes uses a multi-layered test suite covering backend logic, security constraints, frontend modules, and end-to-end user flows.

## Linting & Static Analysis

```bash
# Python linting
flake8 backend/ --max-line-length=120

# Python static analysis
pylint backend/feed_service.py backend/app.py backend/blueprints/
```

## I. Setup for Local Testing

From the project root:

```bash
# Set up Python virtual environment and dependencies
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt -r backend/requirements-dev.txt

# Install Playwright browser dependencies (for E2E tests)
python -m playwright install chromium --with-deps

# Install Node.js frontend dependencies (for Vitest)
npm install
```

## II. Running Backend Unit Tests

Backend tests require a running Valkey service container for caching checks.

1. **Start Valkey**:
   ```bash
   podman run -d --rm --name sheepvibes-test-valkey -p 6379:6379 docker.io/valkey/valkey:9.1.1
   ```

2. **Run Pytest Unit Suite**:
   ```bash
   python -m pytest -c tests/pytest.ini tests/unit -v
   ```

3. **Stop Valkey**:
   ```bash
   podman stop sheepvibes-test-valkey
   ```

## III. Running Frontend Unit Tests

Frontend tests use [Vitest](https://vitest.dev/) with `jsdom` to test ES6 modules, security sanitizers, URL encoding, and UI components:

```bash
npm test
# Or in watch mode during development:
npx vitest
```

## IV. Running End-to-End (E2E) Tests

End-to-end tests use [Playwright](https://playwright.dev/) to test complete user workflows (infinite scrolling, night mode toggling & localStorage persistence, OPML import and SSE progress):

```bash
# Ensure Valkey is running, then run E2E tests:
python -m pytest -c tests/pytest.ini tests/e2e -v --browser chromium
```

> **Note:** The E2E test harness automatically spins up and tears down an isolated live Flask server subprocess. You can optionally test against an external server by providing `TEST_BASE_URL=http://localhost:5002`.

## V. Testing with Local Dev Environment (Podman)

The project provides `scripts/dev_manager.sh` to spin up a complete pod (App + Valkey + Volume):

```bash
# Start Dev Server (Flask Debug Mode with Hot Reloading):
./scripts/dev_manager.sh up

# Start Production Parity Server (Gunicorn):
./scripts/dev_manager.sh up --prod

# Teardown:
./scripts/dev_manager.sh down
```

## VI. CI/CD Automated Testing

GitHub Actions runs the full test suite on every push and pull request via `.github/workflows/run-tests.yml`. CI dynamically maps Valkey's port `6379` and passes it via `CACHE_VALKEY_PORT`.
