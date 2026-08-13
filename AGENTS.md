# AI Agents must respect the following rules

- **Dependency & Version Policy**: Never downgrade dependencies, tools, or GitHub Action versions on a whim or based on outdated training assumptions. Always keep the latest release versions and empirically verify actual existence before making version changes.

## An Agent must always start by reading **all** `.md` files from the repository in order to have a global understanding of the application. They must also read both backend & frontend code files to understand the app's logic. 

## Agents' workflow :

### During a single task, for each of its individual and intermediate step, an Agent must always:
1. Add new relevant tests to the test suite.
2. Verify that pre-existing tests are still valid, and correct them if necessary.
3. Then, validate all tests by executing the full dedicated CI workflow as described in this document.
4. Only then, start the next step.
  
### Finishing a task :
5. Before preparing to end a task it is necessary to run a last full validation of all tests (Vitest frontend, Pytest unit, and Playwright E2E suites).
6. Then it is necessary to update all relevant .md files (*especially* `TODO.md` and `CHANGELOG.md`) accordingly.
7. Only then will the task be completed, and changes be submitted / committed.

### Tag & Release Workflow
- **Automated GHCR & GitHub Releases**: Pushing a version tag matching `v*.*` (e.g. `v0.27`) triggers `.github/workflows/release.yml`, which automatically builds and publishes the container image to `ghcr.io/sheepdestroyer/sheepvibes:<TAG>` and `:latest`, and generates/updates the corresponding GitHub Release notes with the GitHub API.
- **Manual releases**: Can also be drafted or triggered via `gh release create <tag> --generate-notes` or the `workflow_dispatch` trigger in `.github/workflows/release.yml`.

### Tooling for Agents
- **`scripts/dev_manager.sh`**: Use this script to easily spin up a full development environment (App + Valkey) in a pod for integration testing or verification.
  - `up [port] [--prod]`: Starts the environment (use `--prod` for Gunicorn).
  - `down [--clean]`: Stops it (use `--clean` to wipe data).

## CI/CD and Automated Agent Execution Guide

Automated environments, such as those used by Google's Jules, operate in restricted settings where service ports may be mapped dynamically. The project's test suite is designed to handle this.

**The most reliable reference is the project's own CI workflow, located at `.github/workflows/run-tests.yml`.** This file demonstrates exactly how to set up the environment and execute the tests. Agents should replicate this setup.

### Key Configuration Points for Automated Agents:

1.  **Service Containerization**: The tests require a running Valkey service for caching checks. In the GitHub Actions workflow, this is accomplished using the `services` block to start a `docker.io/valkey/valkey:9.1.1` container. Your environment must provide a Valkey container accessible to the test runner.

2.  **Dynamic Port Handling**: In CI systems, you cannot assume Valkey will be available on `localhost:6379`. The service container's port `6379` will be mapped to a *dynamic port* on the host runner. The GitHub Actions workflow retrieves this port using `${{ job.services.valkey.ports['6379'] }}`.

3.  **Environment Variable**: The test suite (`tests/unit/test_app.py`) is explicitly configured to look for the `CACHE_VALKEY_PORT` environment variable (with fallback to `CACHE_REDIS_PORT`). If this variable is set, it will override the default Valkey port and allow the tests to connect to the dynamically mapped port of the Valkey service container.

### Actionable Steps for Automated Agents:

To successfully run the test suite, please follow this procedure, which mirrors our CI workflow:

1.  **Start a Valkey service container** within your environment, and **Identify the host port** that has been dynamically mapped to the container's internal port `6379`.
2.  **Set the `CACHE_VALKEY_PORT` environment variable** to this dynamically assigned port number.
3.  From the project root, **Install dependencies**: `pip install -r backend/requirements.txt -r backend/requirements-dev.txt && npm install`.
4.  **Run backend unit tests**: `python -m pytest -c tests/pytest.ini tests/unit -v`.
5.  **Run frontend unit tests**: `npm test`.
6.  **Run Playwright E2E tests**: `python -m pytest -c tests/pytest.ini tests/e2e -v --browser chromium`.

By following these instructions, which mirror the setup in our own CI workflow, automated tools should be able to execute the full test suite correctly. Always ensure it succeeds before submitting your changes.
