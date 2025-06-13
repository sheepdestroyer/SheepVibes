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

## Deployment with systemd (Recommended)

The recommended way to run SheepVibes is as a `systemd` user service using Podman's Quadlet files. This setup ensures that the application and its Redis cache start automatically on boot and are managed reliably.

**Quick Start:**
1.  Build the app image: `./scripts/rebuild_container.sh`mk
2.  Copy quadlets: `mkdir -p ~/.config/containers/systemd/ && cp quadlets/* ~/.config/containers/systemd/`
3.  Reload systemd: `systemctl --user daemon-reload`
4.  Start the service: `systemctl --user start sheepvibes-app.service`
5.  (Optional) Enable autostart on boot: `loginctl enable-linger $(whoami)`

## Manual Deployment with Podman

If you prefer to manage the containers manually for development or testing, you can use the `podman run` commands directly.

1.  **Run Redis:**
    ```bash
    podman run -d --name sheepvibes-redis -p 127.0.0.1:6379:6379 --restart unless-stopped redis:alpine
    ```

2.  **Run the Application:**
    Ensure you have built the application image first using `./scripts/rebuild_container.sh`.
    ```bash
    podman run -d --name sheepvibes-app \
      -p 127.0.0.1:5000:5000 \
      -v sheepvibes-data:/app/data \
      --restart unless-stopped \
      --network=host \
      localhost/sheepvibes-app:latest
    ```
    *   `--network=host`: This is a simple way for the app container to find Redis at `localhost:6379` during development. For production, a dedicated Podman network is recommended (as used in the Quadlets).

## Configuration (Environment Variables)

You can configure the application by passing environment variables. When using the Quadlets, you can modify the `Environment=` lines in `quadlets/sheepvibes-app.container`. For manual runs, use the `-e` flag with `podman run`.

*   `DATABASE_PATH`: The full path *inside the container* where the SQLite database file should be stored. Defaults to `/app/data/sheepvibes.db`.
*   `UPDATE_INTERVAL_MINUTES`: The interval (in minutes) at which the application checks feeds for updates. Defaults to `15`.
*   `CACHE_REDIS_URL`: The connection URL for the Redis server. The Quadlet default is `redis://sheepvibes-redis:6379/0`, which uses the container's hostname. For manual runs, you might use `redis://localhost:6379/0`.

## Development

1.  **Prerequisites:**
    *   Ensure you have Python 3, `pip`, and a running Redis server.

2.  **Set up Backend Virtual Environment:**
    *   Navigate to the `backend` directory: `cd backend`
    *   Create a virtual environment: `python -m venv venv`
    *   Activate it: `source venv/bin/activate`
    *   Install dependencies: `pip install -r requirements.txt && pip install -r requirements-dev.txt`

3.  **Run the Development Server:**
    The `run_dev.sh` script starts the Flask backend server, which is useful for rapid development.
    ```bash
    ./scripts/run_dev.sh
    ```

4.  **Rebuilding the Container Image:**
    If you make changes to the application code or the `Containerfile`, you must rebuild the image. This script handles the process of building the `localhost/sheepvibes-app` image, which the `systemd` service uses. It no longer manages running containers.
    ```bash
    # Make sure it's executable first: chmod +x scripts/rebuild_container.sh
    ./scripts/rebuild_container.sh
    ```
    After rebuilding the image, if you are using systemd, you must restart the service to use the new image:
    ```bash
    systemctl --user restart sheepvibes-app.service
    ```
