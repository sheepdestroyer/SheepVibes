#!/bin/bash
set -euo pipefail

# --- Configuration ---
REPO="sheepdestroyer/sheepvibes"
BRANCH="main" # Or specify a tag/commit if preferred
QUADLET_DIR="${HOME}/.config/containers/systemd"
POD_FILENAME="sheepvibes.pod" # New pod filename
# Construct the direct download URL for the raw file content
POD_FILE_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/quadlets/${POD_FILENAME}"

# --- Dependency Checks ---
echo "Checking for dependencies..."
if ! command -v curl &> /dev/null; then # jq is no longer needed
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
echo "Ensuring quadlet directory exists at ${QUADLET_DIR}..."
mkdir -p "${QUADLET_DIR}"
if [ $? -ne 0 ]; then
    echo "Error creating directory ${QUADLET_DIR}. Please check permissions."
    exit 1
fi
echo "Directory ensured."
echo ""

# --- Cleanup Step ---
echo "--- Cleaning up old SheepVibes quadlet and pod files ---"
if [ -d "${QUADLET_DIR}" ]; then
    echo "Found quadlet directory at ${QUADLET_DIR}."
    # Updated find command to include .pod files and the specific old files
    find "${QUADLET_DIR}" -maxdepth 1 \
        \( -name 'sheepvibes-*.container' -o \
           -name 'sheepvibes-*.volume' -o \
           -name 'sheepvibes-*.network' -o \
           -name "${POD_FILENAME}" \) \
        -print -exec rm -f {} \; # Print file and then remove it non-interactively
    echo "Cleanup complete."
else
    echo "No existing quadlet directory found. Skipping cleanup."
fi
echo ""

# --- Fetch and Download Quadlet Pod File ---
echo "Fetching ${POD_FILENAME} from GitHub (${REPO}, branch: ${BRANCH})..."
if curl -sSL -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${POD_FILE_URL}" -o "${QUADLET_DIR}/${POD_FILENAME}"; then
    echo "${POD_FILENAME} downloaded successfully to ${QUADLET_DIR}."
else
    echo "Error downloading ${POD_FILENAME} from ${POD_FILE_URL}."
    echo "Please check the repository path, branch name, filename, and your internet connection."
    exit 1
fi
echo ""

# --- User Instructions ---
echo "Pod file ${POD_FILENAME} deployed to ${QUADLET_DIR}."
echo "The application will use Podman-managed volumes 'sheepvibes-db' and 'sheepvibes-redis' for persistence, defined within the pod."
echo ""
echo "Next steps:"
echo "1. Reload systemd to recognize the new/updated pod file:"
echo "   systemctl --user daemon-reload && systemctl --user list-unit-files 'sheepvibes*'"
echo ""
echo "2. Start the pod service (this will start all containers defined in the pod):"
echo "   systemctl --user start ${POD_FILENAME%.*}.service" # Uses the pod filename (e.g., sheepvibes.service)
echo ""
echo "3. Check the status of the pod:"
echo "   systemctl --user status ${POD_FILENAME%.*}.service"
echo "   You can inspect the auto-created volumes with: podman volume inspect sheepvibes-db sheepvibes-redis"
echo ""
echo "4. View logs for the entire pod (follow for real-time updates):"
echo "   journalctl --user -u ${POD_FILENAME%.*}.service -f"
echo "   To view logs for a specific container within the pod (e.g., sheepvibes-app):"
echo "   journalctl --user -u sheepvibes.service -t sheepvibes-app # Assuming systemd uses container name as identifier for journald"
echo "   Alternatively, use 'podman logs <container_name_or_id>'"
echo ""
echo "To stop the pod:"
echo "   systemctl --user stop ${POD_FILENAME%.*}.service"
echo ""
echo "To enable the pod to start automatically when you log in:"
echo "   systemctl --user enable ${POD_FILENAME%.*}.service"
echo ""
echo "Deployment script finished."
