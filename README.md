# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes & iGoogle, designed to run in a Podman container.

## Features

*   Organize grids of feeds into customizable tabs, like Netvibes / iGoogle
*   Import/Export tabs and feeds as OPML files (tested with exports from Netvibes).
*   Add feeds via URL.
*   Delete feeds.
*   Create, rename, and delete tabs.
*   Automatic background fetching of feed updates.
*   Real-time UI updates when feeds are refreshed in the background, powered by Server-Sent Events (SSE).
*   Mark items as read.
*   Displays unread counts per feed and per tab.
*   Basic persistence using a database.

## Production Deployment (Quadlets)

This section describes how to deploy SheepVibes using Podman Quadlets for systemd user services.

### Prerequisites

- `podman`, `curl` and `jq` installed (the deployment script will check for these).
- Git (optional, if you prefer to clone the repository).

### Setup Instructions

1.  **Obtain the Deployment Script**:

   
    For the stable version, always refer to the `main` branch:
    ```bash
    # Stable version from main:
    curl -O https://raw.githubusercontent.com/sheepdestroyer/sheepvibes/main/scripts/deploy_quadlets.sh
    ```

2.  **Make the Script Executable and Run It**:
    Navigate to where you downloaded the script (or the repository root if cloned).
    The script will fetch the necessary Quadlet files from GitHub (from the `main` branch, as defined within the script itself, unless you are using a modified version from a feature branch that specifies otherwise), copy them to `~/.config/containers/systemd/`, and create a data directory at `~/sheepvibes_data`.

    ```bash
    chmod +x deploy_quadlets.sh # Or scripts/deploy_quadlets.sh if cloned
    ./deploy_quadlets.sh      # Or scripts/deploy_quadlets.sh if cloned
    ```
    The script will check for dependencies, guide you through the process, and inform you of the next steps.

3.  **Manage the Service**:
    After running the deployment script, you will be instructed to:
    -   Reload systemd:
        ```bash
        systemctl --user daemon-reload
        ```
    -   Start the application:
        ```bash
        systemctl --user start sheepvibes-app.service
        ```
    -   Check the status of the main application and its Redis dependency:
        ```bash
        systemctl --user status sheepvibes-app.service sheepvibes-redis.service
        ```
    -   View logs (follow):
        ```bash
        journalctl --user -u sheepvibes-app.service -f
        ```
    The `sheepvibes-redis.service` (for caching) and `sheepvibes.network` (for container communication) will be started automatically as dependencies of `sheepvibes-app.service`. The application data will be stored in managed volumes `sheepvibes-db.volume` and `sheepvibes-redis.volume`.

4.  **Enable Auto-start (Optional)**:
    To start SheepVibes automatically when your user logs in, enable the service:
    ```bash
    systemctl --user enable sheepvibes-app.service
    ```
    Note: For user services to start automatically on boot *without* requiring a login, you may need to enable lingering for your user. This typically requires root privileges:
    ```bash
    sudo loginctl enable-linger $(whoami)
    ```

### Accessing the Application

Once started, the application will be accessible at `http://127.0.0.1:5000` by default (as per `sheepvibes-app.container` PublishPort setting). If you need to access it from other machines, you might need to adjust firewall settings or the `PublishPort` setting in the downloaded `quadlets/sheepvibes-app.container` file (e.g., change to `0.0.0.0:5000:5000`) *before* running the deployment script, or re-run the script after modification (it will overwrite existing quadlet files), then reload/restart the systemd service.

## Local Development

This section describes how to set up SheepVibes for local development and testing. This typically involves cloning the repository to get all source files and the `Containerfile`.

### Prerequisites

- Podman installed.
- Git.
- Python environment (optional, for direct backend/frontend work without containers).

### Building the Container

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/sheepdestroyer/sheepvibes.git
    cd sheepvibes
    ```

2.  **Build the Image**:
    Build the application image using the `Containerfile`:
    ```bash
    podman build -t localhost/sheepvibes-app -f Containerfile .
    ```
    Alternatively, use the provided script:
    ```bash
    # Make sure it's executable first: chmod +x scripts/rebuild_container.sh
    ./scripts/rebuild_container.sh
    ```
    After rebuilding the image, if you are using systemd for production, you must restart the service to use the new image: `systemctl --user restart sheepvibes-app.service`


### Running Locally with Podman

1.  **Create a Podman Network**:
    ```bash
    podman network create sheepvibes-dev-network
    ```

2.  **Start Redis Container**:
    ```bash
    podman run -d --name sheepvibes-redis-dev --network sheepvibes-dev-network docker.io/library/redis:alpine
    ```

3.  **Run the Application Container**:
    Create a local directory for the database:
    ```bash
    mkdir -p ./dev_data
    ```
    Run the application container, linking it to Redis and mounting the local data directory:
    ```bash
    podman run -d --name sheepvibes-app-dev \
        --network sheepvibes-dev-network \
        -p 127.0.0.1:5001:5000 \
        -v ./dev_data:/app/data:Z \
        -e DATABASE_PATH=/app/data/sheepvibes.db \
        -e CACHE_REDIS_URL=redis://sheepvibes-redis-dev:6379/0 \
        -e FLASK_APP=backend.app \
        -e PYTHONPATH=/app \
        -e UPDATE_INTERVAL_MINUTES=15 \
        -e FLASK_RUN_HOST=0.0.0.0 \
        localhost/sheepvibes-app
    ```
    You can then access the app at `http://127.0.0.1:5001`. Logs can be viewed with `podman logs sheepvibes-app-dev`.

4.  **Using `run_dev.sh` (Alternative)**:
    The `scripts/run_dev.sh` script provides a way to manage the local development containers. Review and modify it as needed for your local setup.
    *(Note: You might need to update `scripts/run_dev.sh` if it's outdated or doesn't match the above setup. The script primarily focuses on running the backend directly without containers for faster iteration).*

### Direct Backend/Frontend Development

This section is for developers who want to work on the Python backend or JavaScript frontend directly, without running the full application in Podman.

1.  **Prerequisites:**
    *   Ensure you have Python 3, `pip`, and a running Redis server (e.g., `podman run -d --name sheepvibes-redis-direct -p 127.0.0.1:6379:6379 redis:alpine`).

2.  **Set up Backend Virtual Environment (requires cloning the repo):**
    *   Navigate to the `backend` directory: `cd sheepvibes/backend`
    *   Create a virtual environment: `python -m venv venv`
    *   Activate it: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
    *   Install dependencies: `pip install -r requirements.txt && pip install -r requirements-dev.txt`

3.  **Run the Development Server (Flask Backend - requires cloning the repo):**
    The `scripts/run_dev.sh` script can start the Flask backend server directly.
    Ensure `CACHE_REDIS_URL` is set, e.g. `export CACHE_REDIS_URL=redis://localhost:6379/0`
    ```bash
    # from the repository root (e.g., cd sheepvibes)
    ./scripts/run_dev.sh
    ```
    This will typically start the backend on `http://127.0.0.1:5000` (or as configured). The frontend is served statically by Flask in this mode.

## Configuration (Environment Variables)

You can configure the application by passing environment variables.
- When using Quadlets (via `deploy_quadlets.sh`), the script downloads default quadlet files. To customize, you would need to download them manually, edit the `Environment=` lines in `sheepvibes-app.container`, place them in `~/.config/containers/systemd/` *before* running `systemctl --user daemon-reload`, or modify them after deployment and then run `systemctl --user daemon-reload && systemctl --user restart sheepvibes-app.service`.
- When using `podman run` directly, use the `-e` flag.
- When running the backend directly, set them in your shell environment.

*   `DATABASE_PATH`: The full path *inside the container* (or on the host if running directly) where the SQLite database file should be stored. Defaults to `/app/data/sheepvibes.db` (container) or `backend/sheepvibes.db` (direct script).
*   `UPDATE_INTERVAL_MINUTES`: The interval (in minutes) at which the application checks feeds for updates. Defaults to `15`.
*   `CACHE_REDIS_URL`: The connection URL for the Redis server.
    *   Quadlet default (downloaded by script): `redis://sheepvibes-redis:6379/0`
    *   `podman run` dev example: `redis://sheepvibes-redis-dev:6379/0`
    *   Direct script: `redis://localhost:6379/0` (if Redis is on host)
*   `FLASK_APP`: Path to the Flask application. Defaults to `backend.app`.
*   `PYTHONPATH`: Python module search path. Defaults to `/app` in container.
*   `FLASK_RUN_HOST`: Host for Flask development server. Defaults to `0.0.0.0` to be accessible.
  
## Contributing
(Contributions are welcome. Please open an issue or PR.)

## License
(This project is under a GNU General Public License v3.0 License)
