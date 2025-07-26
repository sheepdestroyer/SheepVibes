An Agent must always start by reading **all** .md files from the repository in order to have a global understanding of the application.
It is also important to read both backend & frontend code files to understand the app's logic.

## During a single task, for each of its individual and intermediate step, an Agent must always:
- Add new relevant tests to the test suite.
- Verify that pre-existing tests are still valid, and correct them if necessary.
- Then, validate all tests by executing the full dedicated CI workflow as described in this document.
- Only then, start the next step.
  
## Finishing a task :
- Before preparing to end a task it is necessary to run a last full validation of all tests.
- Then it is necessary to update all relevant .md files (especially TODO.md and CHANGELOG.md) accordingly.
- Only then will the task be completed, and changes be sumbitted / commited.

### CI/CD and Automated Agent Execution Guide

Automated environments, such as those used by Google's Jules, operate in restricted settings where service ports may be mapped dynamically. The project's test suite is designed to handle this.

**The most reliable reference is the project's own CI workflow, located at `.github/workflows/run-tests.yml`.** This file demonstrates exactly how to set up the environment and execute the tests. Agents should replicate this setup.

#### Key Configuration Points for Automated Agents:

1.  **Service Containerization**: The tests require a running Redis service for caching checks. In the GitHub Actions workflow, this is accomplished using the `services` block to start a `redis:alpine` container. Your environment must provide a Redis container accessible to the test runner.

2.  **Dynamic Port Handling**: In CI systems, you cannot assume Redis will be available on `localhost:6379`. The service container's port `6379` will be mapped to a *dynamic port* on the host runner. The GitHub Actions workflow retrieves this port using `${{ job.services.redis.ports['6379'] }}`.

3.  **Environment Variable**: The test suite (`backend/test_app.py`) is explicitly configured to look for the `CACHE_REDIS_PORT` environment variable. If this variable is set, it will override the default Redis port and allow the tests to connect to the dynamically mapped port of the Redis service container.

#### Actionable Steps for Automated Agents:

To successfully run the backend tests, please follow this procedure, which mirrors our CI workflow:

1.  **Start a Redis service container** within your environment.
2.  **Identify the host port** that has been dynamically mapped to the container's internal port `6379`.
3.  **Set the `CACHE_REDIS_PORT` environment variable** to this dynamically assigned port number.
4.  Navigate to the `backend` directory.
5.  **Install dependencies**: `pip install -r requirements.txt -r requirements-dev.txt`.
6.  **Run the tests** using the command: `python -m pytest -v`.

By following these instructions, which mirror the setup in our own CI workflow, automated tools should be able to execute the full test suite correctly. Always ensure it succeeds before submitting your changes.
