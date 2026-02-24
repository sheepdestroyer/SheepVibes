# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes & iGoogle, designed to run in a Podman container.

## Features

*   **Feed Management**: Add, delete, and edit RSS/Atom feeds.
*   **Tabbed Organization**: Organize feeds into customizable tabs, similar to Netvibes and iGoogle.
*   **OPML Support**: Import and export your feeds and tabs as OPML files.
*   **Background Updates**: Automatically fetches feed updates in the background.
*   **Real-Time UI**: The user interface updates in real-time when feeds are refreshed, thanks to Server-Sent Events (SSE).
*   **Unread Tracking**: Mark items as read and see unread counts for each feed and tab.
*   **Persistence**: Your data is saved in a persistent database.

## Project Structure

*   `.github/workflows/`: Contains GitHub Actions workflows for automated testing.
*   `backend/`: The Python Flask backend.
    *   `app.py`: The main Flask application file, containing API endpoints and application logic.
    *   `feed_service.py`: Handles fetching, parsing, and processing of RSS/Atom feeds.
    *   `models.py`: Defines the database schema using SQLAlchemy.
    *   `test_app.py`, `test_feed.py`: Pytest tests for the backend.
*   `frontend/`: The vanilla JavaScript frontend.
    *   `index.html`: The main HTML file.
    *   `script.js`: The main JavaScript file, containing all frontend logic.
    *   `style.css`: The stylesheet for the application.
*   `pod/`: Contains pod file for deploying the application with systemd and Podman.
*   `scripts/`: Contains helper scripts for deployment and development.

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

To maintain code quality, we use `pylint`. It is highly recommended to run it before submitting pull requests:
```bash
# From the root directory
pylint backend/feed_service.py backend/app.py
```
A high score (9.0+) is generally expected for new contributions.

### Accessing the Application

Once started, the application will be accessible at `http://127.0.0.1:5001` by default. To access the application from other machines, you may need to modify the `PublishPort` setting in `~/.config/containers/systemd/sheepvibespod.pod` (e.g., to `0.0.0.0:5001:5000`) and then run `systemctl --user daemon-reload && systemctl --user restart sheepvibespod-pod.service`.

## Local Development

This section describes how to set up SheepVibes for local development.

### Prerequisites

*   Podman
*   Git
*   Python 3 and `pip`

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

The `scripts/dev_manager.sh` script simplifies managing the development environment (App + Redis + Persistence).

1.  **Start the Dev Environment**:
    ```bash
    ./scripts/dev_manager.sh up [port] [--prod]
    # Example: ./scripts/dev_manager.sh up 5003 --prod
    ```
    This will build the image (if needed), create a pod, start Redis, and launch the Backend App.
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

2.  **Start Redis Container**:
    ```bash
    podman run -d --name sheepvibes-redis-dev --network sheepvibes-dev-network docker.io/library/redis:alpine
    ```

3.  **Run the Application Container**:
    ```bash
    mkdir -p ./dev_data
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
    The app will be accessible at `http://127.0.0.1:5001`.

### Direct Backend/Frontend Development

1.  **Prerequisites**:
    *   A running Redis server.

2.  **Set up Backend Virtual Environment**:
    *   Navigate to the `backend` directory: `cd sheepvibes/backend`
    *   Create a virtual environment: `python -m venv venv`
    *   Activate it: `source venv/bin/activate`
    *   Install dependencies: `pip install -r requirements.txt && pip install -r requirements-dev.txt`

3.  **Run the Development Server**:
    The `scripts/run_dev.sh` script can start the Flask backend server.
    ```bash
    ./scripts/run_dev.sh
    ```

## Configuration (Environment Variables)

*   `DATABASE_PATH`: The path to the SQLite database file.
*   `UPDATE_INTERVAL_MINUTES`: The interval in minutes for checking for feed updates.
*   `CACHE_REDIS_URL`: The URL for the Redis server.
*   `FLASK_APP`: The path to the Flask application.
*   `PYTHONPATH`: The Python module search path.
*   `FLASK_RUN_HOST`: The host for the Flask development server.

## Contributing
Contributions are welcome. Please open an issue or pull request.

## Security

*   **XML Parsing**: This project uses a centralized `backend/utils/xml_utils.py` module for all XML operations. It leverages `defusedxml` for secure parsing to protect against XXE attacks. Developers must follow the guidelines in [security_xml.md](file:///home/sheepdestroyer/LAB/SheepVibes/security_xml.md).

## License
This project is licensed under the GNU General Public License v3.0.
