# SheepVibes Quadlets for systemd

These files allow you to run the SheepVibes application and its Redis cache as `systemd` services using Podman. This is the recommended way to deploy the application for automatic startup and management.

## Files

*   `sheepvibes.network`: Creates a dedicated network for the services to communicate securely.
*   `sheepvibes-redis-volume.volume`: Defines a persistent volume for Redis data.
*   `sheepvibes-db-volume.volume`: Defines a persistent volume for the application's SQLite database.
*   `redis.container`: Defines the Redis container service. It uses the `sheepvibes.network` and `sheepvibes-redis-volume.volume`.
*   `sheepvibes-app.container`: Defines the main application service. It depends on the Redis service and the database volume.

## Installation and Management

1.  **Build the Application Image:**
    Before starting the services, you must build the local application image. From the project root, run:
    ```bash
    ./scripts/rebuild_container.sh
    ```

2.  **Copy Quadlet Files:**
    Copy these unit files to your local systemd user directory:
    ```bash
    mkdir -p ~/.config/containers/systemd/
    cp quadlets/* ~/.config/containers/systemd/
    ```

3.  **Reload systemd:**
    Tell systemd to detect the new service files:
    ```bash
    systemctl --user daemon-reload
    ```

4.  **Start the Services:**
    Start the main application service. `systemd` will automatically start the Redis dependency as well.
    ```bash
    systemctl --user start sheepvibes-app.service
    ```

5.  **Enable Auto-start on Boot:**
    To have the services start automatically when you log in, enable the main service:
    ```bash
    systemctl --user enable sheepvibes-app.service
    ```
    For the services to start at boot (even if you are not logged in), you must enable lingering for your user:
    ```bash
    loginctl enable-linger $(whoami)
    ```

## Daily Management

*   **Check Status:** `systemctl --user status sheepvibes-app.service redis.service`
*   **View Logs:** `journalctl --user -u sheepvibes-app.service -f`
*   **Stop Services:** `systemctl --user stop sheepvibes-app.service` (Redis will also be stopped if no other services depend on it).
*   **Restart Services:** `systemctl --user restart sheepvibes-app.service`
