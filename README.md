# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes & iGoogle, designed to run in a Podman container.

## Features

*   **Multi-User & Role-Based Access Control**: Complete multi-tenant isolation, secure session cookies, user management, and user roles (`user` vs `admin`). See [Multi-User Guide](docs/multi-user.md).
*   **First-Run Onboarding Wizard**: Interactive onboarding screen on initial deployment to initialize the master administrator account.
*   **Administration Panel**: Web-based admin dashboard for user account management, password resets, system diagnostics, and non-blocking point-in-time database snapshot backups.
*   **Feed Management**: Add, delete, and edit RSS/Atom feeds with canonical short name derivation.
*   **Tabbed Organization**: Organize feeds into customizable tabs, similar to Netvibes and iGoogle, with independent per-user namespaces.
*   **OPML Support**: Import and export your feeds and tabs as OPML files with live progress indicators.
*   **Background Updates**: Automatically fetches feed updates in the background.
*   **Real-Time UI**: The user interface updates in real-time when feeds are refreshed, thanks to Server-Sent Events (SSE).
*   **Unread Tracking**: Mark items as read and see unread counts for each feed and tab.
*   **Night Mode**: Built-in dark theme with WCAG 2.1 AA contrast compliance and persistent user preferences.
*   **Infinite Scrolling**: Smooth, per-widget progressive loading of feed items.
*   **Persistence**: Your data is saved in a persistent database with user-partitioned versioned caching.

## Project Structure

*   `.github/workflows/`: GitHub Actions workflows for automated testing (`run-tests.yml`) and container release publishing (`release.yml`).
*   `backend/`: The Python Flask backend.
    *   `app.py`: Flask application factory, server configuration, and blueprint registration.
    *   `blueprints/`: Modular route handlers (`feeds.py`, `opml.py`, `tabs.py`).
    *   `feed_service.py`: Handles secure fetching, parsing, sanitization, and processing of RSS/Atom feeds.
    *   `models.py`: Database models using SQLAlchemy.
    *   `cache_utils.py`: Granular caching utilities and cache invalidation helpers.
    *   `sse.py`: Server-Sent Events notification bus.
*   `frontend/`: Modular vanilla JavaScript frontend.
    *   `index.html`: The main HTML interface.
    *   `js/`: ES6 JavaScript modules (`app.js`, `api.js`, `ui.js`, `utils.js`).
    *   `style.css`: Stylesheet with responsive layout and Night Mode theme tokens.
*   `tests/`: Comprehensive test suites.
    *   `unit/`: Pytest unit tests for backend models, feed service, security, and blueprints.
    *   `e2e/`: Playwright end-to-end integration tests.
    *   `frontend/js/*.test.js`: Vitest unit tests for frontend utility functions, API layer, and UI helpers.
*   `pod/`: Quadlet pod, container, and volume definitions for systemd/Podman deployment.
*   `scripts/`: Automation and development helper scripts (`dev_manager.sh`, `deploy_pod.sh`, `run_dev.sh`, `rebuild_container.sh`).

## Production Deployment (Podman Pod with systemd using Quadlet)

This section describes how to deploy SheepVibes using a Podman Pod managed by systemd user services, leveraging Quadlet for easier unit file management.

### Prerequisites

*   `podman` and `curl` installed.
*   A modern version of Podman that includes Quadlet support.
*   Git (optional, if you prefer to clone the repository).

### Setup Instructions

1.  **Obtain the Deployment Script**:
    ```bash
    curl -O https://raw.githubusercontent.com/sheepdestroyer/sheepvibes/main/scripts/deploy_pod.sh
    ```

2.  **Make the Script Executable and Run It**:
    The script will download the necessary Quadlet files to `~/.config/containers/systemd/`.
    ```bash
    chmod +x deploy_pod.sh
    ./deploy_pod.sh
    ```

3.  **Manage the Service**:
    After running the deployment script, you will be instructed to:
    -   Reload systemd to recognize the new Quadlet files:
        ```bash
        systemctl --user daemon-reload
        ```
    -   Start the main pod service:
        ```bash
        systemctl --user start sheepvibespod-pod.service
        ```
    -   Check the status of the pod:
        ```bash
        systemctl --user status sheepvibespod-pod.service
        ```
    -   View logs for the entire pod:
        ```bash
        journalctl --user -u sheepvibespod-pod.service -f
        ```

4.  **Enable Auto-start (Optional)**:
    The `pod/sheepvibespod.pod` file includes an `[Install]` section that enables the service to start automatically with your user session. For the service to start at boot (without requiring a login), you may need to enable lingering for your user:
    ```bash
    sudo loginctl enable-linger $(whoami)
    ```

### Static Analysis & Linting

To maintain code quality, we use `pylint` and `flake8`:
```bash
# Lint backend
flake8 backend/ --max-line-length=120
pylint backend/feed_service.py backend/app.py backend/blueprints/
```

### Accessing the Application

Once started in the production Quadlet, the application is available at `http://127.0.0.1:5002` (container port `5000`). To expose it through a controlled ingress, keep the host binding on `127.0.0.1:5002` and route through HAProxy; do not publish the production container directly on a LAN address. After changing `PublishPort`, run `systemctl --user daemon-reload && systemctl --user restart sheepvibespod-pod.service`.

## Local Development

This section describes how to set up SheepVibes for local development.

### Prerequisites

*   Podman
*   Git
*   Python 3 and `pip`
*   Node.js (for frontend unit tests)

### Building the Container

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/sheepdestroyer/sheepvibes.git
    cd sheepvibes
    ```

2.  **Build the Image**:
    ```bash
    podman build -t localhost/sheepvibes-app -f Containerfile .
    ```
    Or use the provided script:
    ```bash
    ./scripts/rebuild_container.sh
    ```
    After rebuilding the image, if you are using systemd for production, you must restart the service to use the new image: `systemctl --user restart sheepvibespod-pod.service`.

### Running Locally with Podman (Development Manager)

The `scripts/dev_manager.sh` script simplifies managing the development environment (App + Valkey + Persistence).

1.  **Start the Dev Environment**:
    ```bash
    ./scripts/dev_manager.sh up [port] [--prod]
    # Example: ./scripts/dev_manager.sh up 5003 --prod
    ```
    This will build the image (if needed), create a pod, start Valkey, and launch the Backend App.
    - **Default**: Debug Mode (Flask Development Server) with **Hot Reloading**.
    - **--prod**: Production Mode (Gunicorn) with debug disabled.
    The app is exposed on the specified port (default 5002).

2.  **Stop the Dev Environment**:
    ```bash
    ./scripts/dev_manager.sh down
    ```
    This removes the pod and containers but **preserves** the database volume.

3.  **Stop and Clean Data**:
    ```bash
    ./scripts/dev_manager.sh down --clean
    ```
    This removes the pod, containers, **and** the data volume.

### Running Locally with Podman (Manual)

1.  **Create a Podman Network**:
    ```bash
    podman network create sheepvibes-dev-network
    ```

2.  **Start Valkey Container**:
    ```bash
    podman run -d --name sheepvibes-valkey-dev --network sheepvibes-dev-network docker.io/valkey/valkey:9.1.1
    ```

3.  **Run the Application Container**:
    ```bash
    mkdir -p ./dev_data
    podman run -d --name sheepvibes-app-dev \
        --network sheepvibes-dev-network \
        -p 127.0.0.1:5001:5000 \
        -v ./dev_data:/app/data:Z \
        -e DATABASE_PATH=/app/data/sheepvibes.db \
        -e CACHE_VALKEY_URL=redis://sheepvibes-valkey-dev:6379/0 \
        -e FLASK_APP=backend.app \
        -e PYTHONPATH=/app \
        -e UPDATE_INTERVAL_MINUTES=15 \
        -e FLASK_RUN_HOST=0.0.0.0 \
        localhost/sheepvibes-app
    ```
    The app will be accessible at `http://127.0.0.1:5001`.

### Direct Backend/Frontend Development

1.  **Prerequisites**:
    *   A running Valkey server (e.g. `docker.io/valkey/valkey:9.1.1` on port 6379).

2.  **Set up Backend Virtual Environment**:
    *   Create and activate a virtual environment from project root: `python -m venv venv && source venv/bin/activate`
    *   Install dependencies: `pip install -r backend/requirements.txt -r backend/requirements-dev.txt`
    *   Install frontend testing dependencies (optional): `npm install`

3.  **Run the Development Server**:
    The `scripts/run_dev.sh` script starts the Flask backend server with Valkey connectivity checks:
    ```bash
    ./scripts/run_dev.sh
    ```

## Configuration (Environment Variables)

*   `DATABASE_PATH`: Path to the SQLite database file (default: `instance/sheepvibes.db` or `/app/data/sheepvibes.db` in container).
*   `UPDATE_INTERVAL_MINUTES`: Recurring interval in minutes for background feed update scheduler (default: 15).
*   `CACHE_VALKEY_URL`: Connection URL for the Valkey caching service (default: `redis://localhost:6379/0`; fallback supported via `CACHE_REDIS_URL`).
*   `CACHE_VALKEY_PORT`: Dynamic host port override used by automated CI test runners.
*   `FEED_FETCH_TIMEOUT`: Network timeout in seconds for downloading external feed content (default: 20).
*   `MAX_CONCURRENT_FETCHES`: Maximum concurrent worker threads for fetching feeds in parallel (default: 5, capped at 10).
*   `FLASK_APP`: Flask application entrypoint (`backend.app`).
*   `PYTHONPATH`: Python search path (set to `.` or `/app`).
*   `FLASK_RUN_HOST`: Host bind address for development server (default: `127.0.0.1`).

## Contributing
Contributions are welcome. Please open an issue or pull request.

## License
This project is licensed under the GNU General Public License v3.0.
