## Backend Testing
The backend of SheepVibes is written in Python and uses the `pytest` framework for testing.

### I. Setup for Local Testing
1.  Navigate to the backend directory. Install the necessary development dependencies within a Python virtual environment, including `pytest`:
    ```bash
    cd backend
    python -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt -r requirements-dev.txt
    ```


### II. Running Local Tests
The backend tests require a running Redis instance for caching checks.

1.  **Start Redis**
    Before running the tests, start a Redis container. The `--rm` flag will ensure it is automatically removed when stopped.
    ```bash
    # Using Podman
    podman run -d --rm --name sheepvibes-test-redis -p 6379:6379 redis:alpine

    # Or using Docker
    # docker run -d --rm --name sheepvibes-test-redis -p 6379:6379 redis:alpine
    ```

2.  **Run Pytest**
    Ensure you are in the `backend` directory with the virtual environment activated. The test suite is configured via `pytest.ini` to automatically connect to Redis on `localhost:6379`.
    ```bash
    # From the 'backend' directory
    python -m pytest -v
    ```

3.  **Stop Redis**
    After you've finished testing, you can stop the Redis container.
    ```bash
    podman stop sheepvibes-test-redis
    ```

## Frontend Testing
Currently, there are no automated tests specifically for the frontend JavaScript code.

### Future Considerations
For a vanilla JavaScript application like this, End-to-End (E2E) testing would be a valuable addition. Suitable E2E testing tools include:

* **Playwright:** [https://playwright.dev/](https://playwright.dev/)
* **Cypress:** [https://www.cypress.io/](https://www.cypress.io/)

## Automated Testing with GitHub Actions
To ensure code quality, the project uses a GitHub Actions workflow to run backend tests on every push and pull request. This workflow serves as the definitive guide for setting up an automated testing environment.  
The workflow is defined in `.github/workflows/run-tests.yml`.

## Recommendations for CI/CD and Automated Tools & Agents
The key is to follow the instructions given above, and replicate the setup found in our GitHub Actions workflow, paying close attention to the use of service containers and the `CACHE_REDIS_PORT` environment variable for dynamic port mapping.
