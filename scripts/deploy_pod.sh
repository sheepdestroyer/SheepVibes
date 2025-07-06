#!/bin/bash
set -euo pipefail

# --- Configuration ---
REPO="sheepdestroyer/sheepvibes"
BRANCH="main" # Or specify a tag/commit if preferred
SYSTEMD_USER_DIR="${HOME}/.config/containers/systemd"
POD_FILENAME="sheepvibespod.pod"
# Construct the direct download URL for the raw file content
POD_FILE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/pod/${POD_FILENAME}"

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
echo "--- Cleaning up old SheepVibes systemd files and pod file ---"
if [ -d "${SYSTEMD_USER_DIR}" ]; then
    echo "Found systemd user directory at ${SYSTEMD_USER_DIR}."
    # Updated find command to include .pod files and the specific old files
    find "${SYSTEMD_USER_DIR}" -maxdepth 1 \
        \( -name 'sheepvibes-*.container' -o \
           -name 'sheepvibes-*.volume' -o \
           -name 'sheepvibes-*.network' -o \
           -name "${POD_FILENAME}" \) \
        -print -delete # More efficient: print what's being deleted and delete
    echo "Cleanup complete."
else
    echo "No existing systemd user directory found. Skipping cleanup."
fi
echo ""

# --- Fetch and Download Pod File ---
echo "Fetching ${POD_FILENAME} from GitHub (${REPO}, branch: ${BRANCH})..."
if curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${POD_FILE_URL}" -o "${SYSTEMD_USER_DIR}/${POD_FILENAME}"; then
    echo "${POD_FILENAME} downloaded successfully to ${SYSTEMD_USER_DIR}."
else
    echo "Error downloading ${POD_FILENAME} from ${POD_FILE_URL}."
    echo "Please check the repository path, branch name, filename, and your internet connection."
    exit 1
fi
echo ""

# --- User Instructions ---
echo "Pod file ${POD_FILENAME} deployed to ${SYSTEMD_USER_DIR}."
echo "The application will use Podman-managed volumes 'sheepvibespod-sheepvibes-db' and 'sheepvibespod-sheepvibes-redis' for persistence, defined within the pod."
echo ""
echo "Next steps:"
echo "1. Reload systemd to recognize the new/updated pod file:"
echo "   systemctl --user daemon-reload && systemctl --user list-unit-files 'sheepvibespod*'"
echo ""
echo "2. Start the pod service (this will start all containers defined in the pod):"
echo "   systemctl --user start ${POD_FILENAME%.*}.service" # Uses the pod filename (e.g., sheepvibespod.service)
echo ""
echo "3. Check the status of the pod:"
echo "   systemctl --user status ${POD_FILENAME%.*}.service"
echo "   You can inspect the auto-created volumes with: podman volume inspect sheepvibespod-sheepvibes-db sheepvibespod-sheepvibes-redis"
echo ""
echo "4. View logs for the entire pod (follow for real-time updates):"
echo "   journalctl --user -u ${POD_FILENAME%.*}.service -f"
echo "   To view logs for a specific container within the pod (e.g., sheepvibes-app):"
echo "   journalctl --user -u sheepvibespod.service -t sheepvibes-app # Assuming systemd uses container name as identifier for journald"
echo "   Alternatively, use 'podman logs <container_name_or_id>'"
echo ""
echo "To stop the pod:"
echo "   systemctl --user stop ${POD_FILENAME%.*}.service"
echo ""
echo "To enable the pod to start automatically when you log in:"
echo "   systemctl --user enable ${POD_FILENAME%.*}.service"
echo ""
echo "Deployment script finished."
