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

The recommended way to run SheepVibes is as a `systemd` user service using Podman's Quadlet files.  
This setup ensures that the application and its Redis cache start automatically on boot and are managed reliably.  
On Fedora, you will need podman and podlet packages.

### Quick Start Guide

1.  **Build the Application Image**
    Run the build script to create the container image.
    ```bash
    ./scripts/rebuild_container.sh
    ```

2.  **Install Systemd Unit Files**
    Copy the quadlet files (which define the services, network, and volumes) to the correct systemd user directory.
    ```bash
    mkdir -p ~/.config/containers/systemd/
    cp quadlets/* ~/.config/containers/systemd/
    ```

3.  **Reload Systemd and Verify**
    Tell systemd to reload its configuration to detect the new files, then verify that it has recognized the new services. This is a crucial step.
    ```bash
    systemctl --user daemon-reload
    systemctl --user list-unit-files 'sheepvibes*'
    ```
    The output of the `list-unit-files` command should look similar to this, confirming the services are available:
    ```
    UNIT FILE                              STATE     PRESET
    sheepvibes-app.service                 generated -
    sheepvibes-db-volume-volume.service    generated -
    sheepvibes-network.service             generated -
    sheepvibes-redis-volume-volume.service generated -
    ```
    If you see this output, you can proceed. If the files are not listed, see the **Troubleshooting** section below.

4.  **Start the Application**
    Start the main application service. Systemd will automatically start its dependencies (the Redis container, network, and volumes).
    ```bash
    systemctl --user start sheepvibes-app.service
    ```
    You can check the status of all related services with: `systemctl --user status 'sheepvibes*' redis.service`

5.  **(Optional) Enable Auto-start on Boot**
    To have the services start automatically when you log in, enable the main service. For this to work on system startup (before you log in), you must also enable lingering for your user.
    ```bash
    systemctl --user enable sheepvibes-app.service
    loginctl enable-linger $(whoami)
    ```

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

## Troubleshooting

### Error: `Unit ... not found`

If you run a `systemctl --user` command and receive an error like `Failed to start sheepvibes-app.service: Unit sheepvibes-app.service not found`, it means `systemd` was unable to generate the service file from the quadlet definitions.

This is typically caused by one of two issues:
1.  **Files in wrong location:** The quadlet files (e.g., `sheepvibes-app.container`) were not placed in `~/.config/containers/systemd/`.
2.  **Systemd not reloaded:** `systemctl --user daemon-reload` was not executed after the files were copied.

To resolve this, carefully follow these steps:
1.  **Verify the files exist:** Run `ls -l ~/.config/containers/systemd/` and check for all `.container`, `.network`, and `.volume` files. If any are missing, copy them again: `cp quadlets/* ~/.config/containers/systemd/`.
2.  **Reload the systemd daemon:** Run `systemctl --user daemon-reload`.
3.  **Check if the service is now visible:** Run `systemctl --user list-unit-files 'sheepvibes*'` to confirm.

If the services are still not found, check that the `podman-quadlet` package (or your distribution's equivalent) is installed.
