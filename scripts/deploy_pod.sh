#!/bin/bash
set -euo pipefail

# --- Configuration ---
REPO="sheepdestroyer/sheepvibes"
BRANCH="main" # Or specify a tag/commit if preferred
SYSTEMD_USER_DIR="${HOME}/.config/containers/systemd"
# Define the Quadlet files to be downloaded
QUADLET_FILES=(
    "sheepvibespod.pod"
    "sheepvibes-app.container"
    "sheepvibes-redis.container"
    "sheepvibes-db.volume"
    "sheepvibes-redis-data.volume"
)
# Base URL for the directory containing the Quadlet files in the repository
QUADLET_BASE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/pod/quadlet"

# --- Dependency Checks ---
echo "Checking for dependencies..."
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install curl and try again."
    exit 1
fi
if ! command -v podman &> /dev/null; then
    echo "Error: podman is not installed. Please install podman and try again."
    exit 1
fi
echo "Dependencies found."
echo ""

# --- Create Target Directory ---
echo "Ensuring systemd user directory exists at ${SYSTEMD_USER_DIR}..."
mkdir -p "${SYSTEMD_USER_DIR}"
if [ $? -ne 0 ]; then
    echo "Error creating directory ${SYSTEMD_USER_DIR}. Please check permissions."
    exit 1
fi
echo "Directory ensured."
echo ""

# --- Cleanup Step ---
echo "--- Cleaning up old SheepVibes systemd files ---"
if [ -d "${SYSTEMD_USER_DIR}" ]; then
    echo "Found systemd user directory at ${SYSTEMD_USER_DIR}."
    # Remove old monolithic pod file and any files matching the new names
    find "${SYSTEMD_USER_DIR}" -maxdepth 1 \
        \( -name 'sheepvibespod.pod' \
           -o -name 'sheepvibes-app.container' \
           -o -name 'sheepvibes-redis.container' \
           -o -name 'sheepvibes-db.volume' \
           -o -name 'sheepvibes-redis-data.volume' \
           -o -name 'sheepvibes-*.network' \) \
        -print -delete
    echo "Cleanup complete."
else
    echo "No existing systemd user directory found. Skipping cleanup."
fi
echo ""

# --- Fetch and Download Quadlet Files ---
echo "Fetching Quadlet files from GitHub (${REPO}, branch: ${BRANCH}, path: pod/quadlet/)..."
DOWNLOAD_SUCCESS=true
for filename in "${QUADLET_FILES[@]}"; do
    file_url="${QUADLET_BASE_URL}/${filename}"
    echo "Downloading ${filename} from ${file_url}..."
    if curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${file_url}" -o "${SYSTEMD_USER_DIR}/${filename}"; then
        echo "${filename} downloaded successfully to ${SYSTEMD_USER_DIR}."
    else
        echo "Error downloading ${filename} from ${file_url}."
        DOWNLOAD_SUCCESS=false
    fi
done

if [ "${DOWNLOAD_SUCCESS}" = false ]; then
    echo "One or more files failed to download."
    echo "Please check the repository path, branch name, filenames in pod/quadlet/, and your internet connection."
    exit 1
fi
echo ""

# --- User Instructions ---
POD_SERVICE_NAME="sheepvibespod-pod.service" # Generated from sheepvibespod.pod
DB_VOLUME_NAME="systemd-sheepvibes-db" # Default generated name from sheepvibes-db.volume
REDIS_VOLUME_NAME="systemd-sheepvibes-redis-data" # Default generated name from sheepvibes-redis-data.volume

echo "Quadlet files deployed to ${SYSTEMD_USER_DIR}."
echo "The application will use Podman-managed volumes '${DB_VOLUME_NAME}' and '${REDIS_VOLUME_NAME}' for persistence."
echo ""
echo "Next steps:"
echo "1. Reload systemd to recognize the new/updated Quadlet files:"
echo "   systemctl --user daemon-reload"
echo "   After reloading, check if Quadlet generated all services:"
echo "   ls -la /run/user/\$(id -u)/systemd/generator/"
echo "   Check the Quadlet generator logs for any errors:"
echo "   journalctl --user -u systemd-quadlet-generator.service --no-pager --since \"5 minutes ago\""
echo ""
echo "2. List the generated unit files to confirm:"
echo "   systemctl --user list-unit-files 'sheepvibes*'"
echo ""
echo "3. Start the main pod service (this will start all containers and create volumes as defined):"
echo "   systemctl --user start ${POD_SERVICE_NAME}"
echo ""
echo "4. Check the status of the pod and its components:"
echo "   systemctl --user status ${POD_SERVICE_NAME}"
echo "   systemctl --user status sheepvibes-app.service"
echo "   systemctl --user status sheepvibes-redis.service"
echo "   systemctl --user status sheepvibes-db-volume.service"
echo "   systemctl --user status sheepvibes-redis-data-volume.service"
echo ""
echo "5. Inspect the auto-created volumes:"
echo "   podman volume inspect ${DB_VOLUME_NAME} ${REDIS_VOLUME_NAME}"
echo ""
echo "6. View logs for the entire pod (follow for real-time updates):"
echo "   journalctl --user -u ${POD_SERVICE_NAME} -f"
echo "   To view logs for a specific container (e.g., sheepvibes-app):"
# The -t option with the pod service is good, or directly query the container's service
echo "   journalctl --user -u ${POD_SERVICE_NAME} -t sheepvibes-app"
echo "   # OR for more detailed logs of just the app container's service:"
echo "   journalctl --user -u sheepvibes-app.service -f"
echo ""
echo "To stop the pod:"
echo "   systemctl --user stop ${POD_SERVICE_NAME}"
echo ""
echo "To enable the pod to start automatically when you log in:"
echo "   systemctl --user enable ${POD_SERVICE_NAME}"
echo ""
echo "Deployment script finished."
