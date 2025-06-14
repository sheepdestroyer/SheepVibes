# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes, built with Flask and Vanilla JavaScript, designed to run in a Podman container.

## Features

*   Organize grids of feeds into customizable tabs, like Netvibes / iGoogle
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

- Podman installed on your server.
- `curl` and `jq` installed (the deployment script will check for these).
- Git (optional, if you prefer to clone the repository).

### Setup Instructions

> **Important Note for `feature/host-dir-writable` Branch Users:**
> The `deploy_quadlets.sh` script obtained from the `feature/host-dir-writable` branch includes **enhanced diagnostic steps**. It will:
> 1. Make the `~/sheepvibes_data` directory world-writable (`chmod 0777`).
> 2. Pre-create the `sheepvibes.db` file in `~/sheepvibes_data` with open permissions (`chmod 0666`) on the host.
> This is for testing purposes ONLY to help diagnose database access issues, particularly "attempt to write a readonly database" errors. This behavior is specific to the script on this branch. For production, use the script from the `main` branch once issues are resolved.

1.  **Obtain the Deployment Script**:

    If you are testing the `feature/host-dir-writable` branch and have cloned the repository, the script is available at `scripts/deploy_quadlets.sh`.

    Alternatively, you can download the version of the script specific to this branch using `curl` or `wget`:

    Using `curl` (for `feature/host-dir-writable` branch):
    ```bash
    curl -O https://raw.githubusercontent.com/sheepdestroyer/sheepvibes/feature/host-dir-writable/scripts/deploy_quadlets.sh
    ```
    Or using `wget` (for `feature/host-dir-writable` branch):
    ```bash
    wget https://raw.githubusercontent.com/sheepdestroyer/sheepvibes/feature/host-dir-writable/scripts/deploy_quadlets.sh
    ```
    For the stable version, always refer to the `main` branch:
    ```bash
    # Stable version from main:
    # curl -O https://raw.githubusercontent.com/sheepdestroyer/sheepvibes/main/scripts/deploy_quadlets.sh
    ```

2.  **Make the Script Executable and Run It**:
    Navigate to where you downloaded the script (or the repository root if cloned).
    The script will fetch the necessary Quadlet files from GitHub (from the `main` branch, as defined within the script itself, unless you are using a modified version from a feature branch that specifies otherwise), copy them to `~/.config/containers/systemd/`, and create a data directory at `~/sheepvibes_data`.

    ```bash
    chmod +x deploy_quadlets.sh # Or scripts/deploy_quadlets.sh if cloned
    ./deploy_quadlets.sh      # Or scripts/deploy_quadlets.sh if cloned
    ```
    The script will check for `curl` and `jq`, guide you through the process, and inform you of the next steps.

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
        systemctl --user status sheepvibes-app.service redis.service
        ```
    -   View logs (follow):
        ```bash
        journalctl --user -u sheepvibes-app.service -f
        ```
    The `redis.service` (for caching) and `sheepvibes.network` (for container communication) will be started automatically as dependencies of `sheepvibes-app.service`. The application data will be stored in `~/sheepvibes_data`.

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
    # If testing this specific feature, checkout the branch:
    # git checkout feature/host-dir-writable
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

## Troubleshooting

### Error: `Unit ... not found` during Quadlet deployment

If you run a `systemctl --user` command and receive an error like `Failed to start sheepvibes-app.service: Unit sheepvibes-app.service not found`, it means `systemd` was unable to generate the service file from the quadlet definitions.

This is typically caused by one of two issues:
1.  **Files not downloaded or in wrong location:** The `deploy_quadlets.sh` script should handle downloading to `~/.config/containers/systemd/`. Verify the script ran successfully and that files like `sheepvibes-app.container` are present there.
2.  **Systemd not reloaded:** `systemctl --user daemon-reload` was not executed after the files were copied or updated. The script should remind you of this.

To resolve this, carefully follow these steps:
1.  **Run the deployment script:** Ensure `./deploy_quadlets.sh` (after downloading and `chmod +x`) completed successfully.
2.  **Verify the files exist:** Run `ls -l ~/.config/containers/systemd/` and check for `sheepvibes-app.container`, `redis.container`, and `sheepvibes.network`.
3.  **Reload the systemd daemon:** Run `systemctl --user daemon-reload`.
4.  **Check if the service is now visible:** Run `systemctl --user list-unit-files 'sheepvibes*'` to confirm.

If the services are still not found, check that the `podlet` or `podman-quadlet` package (your distribution's equivalent) is installed. Also ensure your systemd user instance is running correctly.

### Error: `unable to open database file` (or similar database errors)

If the application logs (viewable with `journalctl --user -u sheepvibes-app.service -f`) show errors like "unable to open database file", "database is locked", or other SQLite errors, it often points to issues with the data directory on the host (`~/sheepvibes_data`) or how the container interacts with it.

*   **Host Directory Permissions**:
    Ensure the data directory (`~/sheepvibes_data` by default) is writable by your user. The deployment script will create it if it doesn't exist (`mkdir -p`). You can verify its permissions on the host machine by running:
    ```bash
    ls -ld ~/sheepvibes_data
    ```
    The user running the container (which is your user when using systemd user services) needs write access.

*   **SELinux Issues**:
    If SELinux is in `enforcing` mode (check with `sestatus`), the container might be denied access to the `~/sheepvibes_data` directory. The `:Z` flag on the `Volume` line in `quadlets/sheepvibes-app.container` (e.g., `Volume=%h/sheepvibes_data:/app/data:Z`) instructs Podman to automatically relabel the host directory to a context like `container_file_t`, which is usually sufficient.

    If issues persist:
    1.  **Verify Directory Context**: Check the current SELinux context of the data directory:
        ```bash
        ls -lZ ~/sheepvibes_data
        ```
        It should ideally have a context like `container_file_t` or similar that containers can access.
    2.  **Set Permanent Context**: If the context is incorrect or missing, the recommended solution is to define a permanent SELinux context rule for the directory and its contents. Replace `YOUR_USERNAME` with your actual username:
        ```bash
        sudo semanage fcontext -a -t container_file_t "/home/YOUR_USERNAME/sheepvibes_data(/.*)?"
        ```
        Then apply this context rule:
        ```bash
        sudo restorecon -Rv ~/sheepvibes_data
        ```
    3.  **Temporary Context (for testing, does not survive relabeling/reboot)**:
        ```bash
        sudo chcon -Rt container_file_t ~/sheepvibes_data
        ```
    4.  **Permissive Mode (for diagnosis ONLY)**: As a last resort for quick diagnosis, you can temporarily set SELinux to permissive mode. **Warning**: This significantly lowers system security and should only be used for brief testing. Revert to enforcing mode immediately after.
        ```bash
        sudo setenforce 0
        # After testing, revert with:
        # sudo setenforce 1
        ```
        If permissive mode works, it confirms an SELinux policy issue, and you should apply a permanent context fix as described above.

## Contributing

(Contributions are welcome. Please open an issue or PR.)

## License

(This project is likely under an MIT License or similar open source license. Please add a LICENSE file.)
```
