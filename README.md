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

## Running with Podman

1.  **Prerequisites:**
    *   Podman installed.


2.  **Create a Persistent Volume (Optional but Recommended):**
    To ensure your database and configuration persist even if the container is removed, create a named volume:
    ```bash
    podman volume create sheepvibes-data
    ```


3.  **Run the Container:**
    *   **With Persistent Volume:**
        ```bash
        podman run -d --name sheepvibes-instance \
          -p 127.0.0.1:5000:5000 \
          -v sheepvibes-data:/app/data \
          --restart unless-stopped \
          --replace \
          ghcr.io/sheepdestroyer/sheepvibes:latest
        ```
        *   `-d`: Run in detached mode (background).
        *   `--name sheepvibes-instance`: Assign a name to the container.
        *   `-p 127.0.0.1:5000:5000`: Map port 5000 on your host to port 5000 in the container. Listens locally (change it to -p 5000:5000 to listen externally, but this app not secure so don't do it)
        *   `-v sheepvibes-data:/app/data`: Mount the named volume to the `/app/data` directory inside the container, where `sheepvibes.db` will be stored.
        *   `--restart unless-stopped`: Automatically restart the container unless manually stopped.
        *   `--replace`: Automatically replace a running container by a new one

    *   **Without Persistent Volume (Data lost if container is removed):**
        ```bash
        podman run -d --name sheepvibes-instance -p 5000:5000 ghcr.io/sheepdestroyer/sheepvibes:latest
        ```


4.  **Access SheepVibes:**
    Open your web browser and navigate to `http://localhost:5000`.

**Note for Developers:** The helper scripts provided in the `scripts/` directory (e.g., `manage_container.sh`, `rebuild_container.sh`) build and use a local image named `sheepvibes-app` by default, rather than the public `ghcr.io` image.

## Configuration (Environment Variables)

You can configure the application by passing environment variables during the `podman run` command using the `-e` flag:

*   `DATABASE_PATH`: The full path *inside the container* where the SQLite database file should be stored. Defaults to `/app/data/sheepvibes.db`. If using the recommended volume mount, this path is within the volume.
    *   Example: `-e DATABASE_PATH=/app/data/my_custom_name.db`
*   `UPDATE_INTERVAL_MINUTES`: The interval (in minutes) at which the application checks feeds for updates. Defaults to `15`.
    *   Example: `-e UPDATE_INTERVAL_MINUTES=30`
      
**Example running with custom configuration:**

```bash
podman run -d --name sheepvibes-instance \
  -p 127.0.0.1:5000:5000 \
  -v sheepvibes-data:/app/data \
  -e UPDATE_INTERVAL_MINUTES=60 \
  --restart unless-stopped \
  --replace \
  ghcr.io/sheepdestroyer/sheepvibes:latest
```

## Development

To run the application locally for development without using Podman, follow these steps:

1.  **Prerequisites:**
    *   Ensure you have Python 3 installed.
    *   Ensure you have `pip` (Python package installer) available.


2.  **Set up Backend Virtual Environment:**
    *   Navigate to the `backend` directory:
        ```bash
        cd backend
        ```
    *   Create a virtual environment (if you haven't already):
        ```bash
        python -m venv venv
        ```
    *   Activate the virtual environment:
        *   On Linux/macOS: `source venv/bin/activate`
        *   On Windows (Git Bash/WSL): `source venv/Scripts/activate`
        *   On Windows (Command Prompt): `venv\Scripts\activate.bat`
        *   On Windows (PowerShell): `venv\Scripts\Activate.ps1`
    *   Install the required Python packages:
        ```bash
        pip install -r requirements.txt
        ```
    *   (Optional) Install development dependencies:
        ```bash
        pip install -r requirements-dev.txt
        ```


3.  **Run the Development Script:**
        ```bash
        ./scripts/run_dev.sh
        ```
    *   This will start the Flask backend development server, typically accessible at `http://localhost:5000`. The script handles activating the virtual environment and setting necessary Flask environment variables.

    *   The application supports the following environment variables:
        - `DATABASE_PATH`: Path to the SQLite database file (default: `/app/data/sheepvibes.db` inside the container, or `data/sheepvibes.db` relative to project root when run locally without the variable set).
        - `UPDATE_INTERVAL_MINUTES`: Interval in minutes for feed updates (default: 15)


4.  **Rebuilding the Image:**
    If you make changes to the application code or the `Containerfile`, you'll need to rebuild the image. A convenience script is provided:
    ```bash
    # Make sure it's executable first: chmod +x scripts/rebuild_container.sh
    ./scripts/rebuild_container.sh 
    ```
    This script will:
    *   Stop the running container named `sheepvibes-instance` (if it exists).
    *   Remove the stopped container `sheepvibes-instance` (if it exists).
    *   Remove the old image tagged `sheepvibes-app` (if it exists).
    *   Build a new image tagged `sheepvibes-app`.
    *   **Note:** The script assumes Podman is used and the container/image names are `sheepvibes-instance`/`sheepvibes-app`. Edit the script if your setup differs.

    After rebuilding, you'll need to run the container again using the `podman run` command from step 3.

5.  **Managing the Container (Start/Stop/Restart):**
    A convenience script is provided to easily start, stop, or restart the `sheepvibes-instance` container without needing to remember the full `podman run` options each time.
    ```bash
    # Make sure it's executable first: chmod +x scripts/manage_container.sh
    
    # Start the container (creates if it doesn't exist)
    ./scripts/manage_container.sh start
    
    # Stop the running container
    ./scripts/manage_container.sh stop
    
    # Restart the container
    ./scripts/manage_container.sh restart
    ```
    *   This script uses the same container name (`sheepvibes-instance`), image name (`sheepvibes-app`), volume (`sheepvibes-data`), and port mapping (`5000:5000`) as defined in the script itself and used in the examples above.
    *   It assumes Podman is used. Edit the `CONTAINER_CMD` variable within the script if you use Docker.
