## Backend Testing

The backend of SheepVibes is written in Python and uses the `pytest` framework for testing.

### Setup

1.  Navigate to the backend directory. Install the necessary development dependencies within a Python virtual environment, including `pytest`:
    ```bash
    cd backend
    python -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt -r requirements-dev.txt
    ```


### Running Tests

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

For a vanilla JavaScript application like this, End-to-End (E2E) testing would be a valuable addition to ensure user interface functionality and behavior. Suitable E2E testing tools include:

*   **Playwright:** [https://playwright.dev/](https://playwright.dev/)
*   **Cypress:** [https://www.cypress.io/](https://www.cypress.io/)

Implementing E2E tests would involve writing test scripts that simulate user interactions with the web interface (e.g., clicking buttons, filling forms, verifying displayed content) and checking that the application responds correctly.

## Automated Testing with GitHub Actions

To ensure code quality and catch regressions early, it's highly recommended to automate the execution of backend tests using GitHub Actions. This section proposes a workflow that runs the tests on every push to the `main` branch and on every pull request targeting `main`.

### Workflow File

The Github automatic workflow is defined in the file named `.github/workflows/run-tests.yml` with the following content:

```yaml
name: Run Backend Tests

on:
  push:
    branches: [ '**' ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      # Start a Redis service container for the job
      redis:
        image: redis:alpine
        # Expose port 6379 on the service container to be mapped to the host
        ports:
          - 6379/tcp
        # Health check for a passwordless Redis service.
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Python 3.13
      uses: actions/setup-python@v5
      with:
        python-version: '3.13'
        cache: 'pip' # Cache pip dependencies

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r backend/requirements.txt -r backend/requirements-dev.txt

    - name: Run Pytest
      env:
        # Pass the dynamically assigned Redis host port to the tests.
        CACHE_REDIS_PORT: ${{ job.services.redis.ports['6379'] }}
      run: |
        cd backend
        python -m pytest -v
```

### Workflow Explanation

*   **`name: Run Backend Tests`**: The name of the workflow as it will appear in the GitHub Actions UI.
*   **`on:`**: Defines the triggers for the workflow.
    *   `push: branches: [ ** ]`: Runs when changes are pushed to any branch.
    *   `pull_request: branches: [ main ]`: Runs when a pull request is opened or updated that targets the `main` branch.
*   **`jobs:`**: Defines one or more jobs to run.
    *   **`test:`**: The name of the job.
        *   `runs-on: ubuntu-latest`: Specifies that the job should run on the latest version of Ubuntu provided by GitHub.
        *   **`services:`**: Defines external services to be run in containers for the job.
            *   `redis:`: A service named `redis` is started using the `redis:alpine` image. It includes a health check to ensure tests don't start until Redis is responsive. This service is automatically available to the job runner at `localhost:6379`.
        *   **`steps:`**: A sequence of tasks to be executed.
            1.  **`Checkout code`**: Uses the standard `actions/checkout@v4` action to download the repository's code into the runner.
            2.  **`Set up Python 3.13`**: Uses the `actions/setup-python@v5` action to install the specified Python version (3.13 in this case).
            3.  **`Install dependencies`**: Executes shell commands to upgrade pip and install the project's runtime and development dependencies from the `requirements.txt` and `requirements-dev.txt` files located in the `backend` directory.
            4.  **`Run Pytest`**: Changes to the `backend` directory and then runs `python -m pytest -v`. The tests automatically connect to the Redis service thanks to the configuration in `pytest.ini`.

### Accessing Workflow Results

After this workflow is added to the repository (in `.github/workflows/run-tests.yml`), it will automatically run based on the triggers defined. You can view the status and logs of each workflow run in the "Actions" tab of your GitHub repository. This will show whether the tests passed or failed, along with any output or errors from the test execution.

## Recommendations for CI/CD and Automated Tools & Agents (like Jules)

Automated environments, such as those used by Google's Jules, often operate in restricted or virtualized settings where service ports may be mapped dynamically. The project's test suite is designed to handle this.

The key to running tests successfully in such an environment is to provide a Redis instance and inform the test suite how to connect to it.

**The most reliable reference is the project's own CI workflow**, located at [`.github/workflows/run-tests.yml`](https://www.google.com/search?q=./.github/workflows/run-tests.yml). This file demonstrates exactly how to set up the environment.

#### Key Configuration Points for Automated Agents:

1.  **Redis Service**: The tests require a running Redis service for caching checks. In the GitHub Actions workflow, this is accomplished using the `services` block to start a `redis:alpine` container. Your environment will need to do the same.

2.  **Dynamic Port Handling**: In many CI systems, you cannot assume Redis will be available on `localhost:6379`. The service container's port `6379` will be mapped to a *dynamic* port on the host runner. The GitHub Actions workflow retrieves this port using `${{ job.services.redis.ports['6379'] }}`.

3.  **Environment Variable**: The test suite (`backend/test_app.py`) is explicitly configured to look for the `CACHE_REDIS_PORT` environment variable. If this variable is set, it will override the default Redis port and allow the tests to connect to the dynamically mapped port of the Redis service container.

#### Actionable Steps for CI/CD Tools:

To successfully run the backend tests, please follow this procedure:

1.  **Start a Redis container** within your environment.
2.  **Identify the host port** that has been dynamically mapped to the container's internal port `6379`.
3.  **Set the `CACHE_REDIS_PORT` environment variable** to this dynamically assigned port number.
4.  Navigate to the `backend` directory.
5.  **Install dependencies**: `pip install -r requirements.txt -r requirements-dev.txt`.
6.  **Run the tests** using the command: `python -m pytest -v`.

By following these instructions, which mirror the setup in our own CI workflow, your automated tool should be able to execute the test suite correctly.
