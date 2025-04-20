# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes, built with Flask and Vanilla JavaScript, designed to run in a Podman container.

## Features

*   Organize feeds into customizable tabs.
*   Add feeds via URL.
*   Delete feeds.
*   Create, rename, and delete tabs.
*   Automatic background fetching of feed updates.
*   Mark items as read.
*   Displays unread counts per feed and per tab.
*   Basic persistence using a SQLite database.

## Running with Podman

1.  **Build the Image:**
    Navigate to the project root directory (where the `Containerfile` is located) and run:
    ```bash
    podman build -t sheepvibes .
    ```

2.  **Create a Persistent Volume (Optional but Recommended):**
    To ensure your database and configuration persist even if the container is removed, create a named volume:
    ```bash
    podman volume create sheepvibes-data
    ```

3.  **Run the Container:**
    *   **With Persistent Volume:**
        ```bash
        podman run -d --name sheepvibes-app \
          -p 5000:5000 \
          -v sheepvibes-data:/app/backend \
          --restart unless-stopped \
          localhost/sheepvibes
        ```
        *   `-d`: Run in detached mode (background).
        *   `--name sheepvibes-app`: Assign a name to the container.
        *   `-p 5000:5000`: Map port 5000 on your host to port 5000 in the container.
        *   `-v sheepvibes-data:/app/backend`: Mount the named volume to the `/app/backend` directory inside the container, where `sheepvibes.db` will be stored.
        *   `--restart unless-stopped`: Automatically restart the container unless manually stopped.

    *   **Without Persistent Volume (Data lost if container is removed):**
        ```bash
        podman run -d --name sheepvibes-app -p 5000:5000 localhost/sheepvibes
        ```

4.  **Access SheepVibes:**
    Open your web browser and navigate to `http://localhost:5000`.

## Configuration (Environment Variables)

You can configure the application by passing environment variables during the `podman run` command using the `-e` flag:

*   `DATABASE_PATH`: The full path *inside the container* where the SQLite database file should be stored. Defaults to `/app/backend/sheepvibes.db`. If using the recommended volume mount, this path is within the volume.
    *   Example: `-e DATABASE_PATH=/app/backend/my_custom_name.db`
*   `UPDATE_INTERVAL_MINUTES`: The interval (in minutes) at which the application checks feeds for updates. Defaults to `15`.
    *   Example: `-e UPDATE_INTERVAL_MINUTES=30`

**Example running with custom configuration:**

```bash
podman run -d --name sheepvibes-app \
  -p 5000:5000 \
  -v sheepvibes-data:/app/backend \
  -e UPDATE_INTERVAL_MINUTES=60 \
  --restart unless-stopped \
  localhost/sheepvibes
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
    *   **Troubleshooting:** If you encounter errors like `ModuleNotFoundError: No module named 'pip'` after activating the environment, the virtual environment might be corrupted. Delete the `backend/venv` directory and recreate it following the steps above.

3.  **Run the Development Script:**
    *   Navigate back to the project root directory:
        ```bash
        cd .. 
        ```
    *   Make the script executable (if you haven't already):
        ```bash
        chmod +x scripts/run_dev.sh
        ```
    *   Execute the script:
        ```bash
        ./scripts/run_dev.sh
        ```
    *   This will start the Flask backend development server, typically accessible at `http://localhost:5000`. The script handles activating the virtual environment and setting necessary Flask environment variables.

4.  **Serve the Frontend:**
    *   The backend API will be running, but you also need to serve the static frontend files (`frontend/index.html`, `frontend/style.css`, `frontend/script.js`).
    *   You can use a simple HTTP server or a tool like VS Code's Live Server extension.
    *   **Example using Python's built-in server (run from the project root):**
        ```bash
        # Make sure you are in the project root directory
        python -m http.server --directory frontend 8000 
        ```
        Then access the frontend at `http://localhost:8000`. The frontend JavaScript (`script.js`) is configured to make requests to the backend API running on port 5000.


### Environment Variables

The application supports the following environment variables:

- `DATABASE_PATH`: Path to the SQLite database file (default: `backend/sheepvibes.db`)
- `UPDATE_INTERVAL_MINUTES`: Interval in minutes for feed updates (default: 15)

### Next Steps

- Frontend implementation (Phase 2)
- User interactivity features (Phase 3)
- Refinement and deployment enhancements (Phase 4)
