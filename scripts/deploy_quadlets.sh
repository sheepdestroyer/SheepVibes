#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
REPO="sheepdestroyer/sheepvibes"
BRANCH="main" # Or specify a tag/commit if preferred
QUADLET_DIR="${HOME}/.config/containers/systemd"
DATA_DIR="${HOME}/sheepvibes_data"
QUADLET_FILES_URL="https://api.github.com/repos/${REPO}/contents/quadlets?ref=${BRANCH}"

# --- Dependency Checks ---
echo "Checking for dependencies..."
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install curl and try again."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq and try again."
    exit 1
fi
echo "Dependencies found."
echo ""

# --- Create Target Directories ---
echo "Creating target directories..."
mkdir -p "${QUADLET_DIR}"
if [ $? -ne 0 ]; then
    echo "Error creating directory ${QUADLET_DIR}. Please check permissions."
    exit 1
fi
mkdir -p "${DATA_DIR}"
if [ $? -ne 0 ]; then
    echo "Error creating directory ${DATA_DIR}. Please check permissions."
    exit 1
fi
echo "Applying diagnostic permissions (0777) to directory ${DATA_DIR}..."
chmod 0777 "${DATA_DIR}" # Diagnostic: Ensure directory is world-writable
echo "Attempting to pre-create database file on host and set permissions: ${DATA_DIR}/sheepvibes.db"
touch "${DATA_DIR}/sheepvibes.db"
chmod 0666 "${DATA_DIR}/sheepvibes.db" # Diagnostic: Make file writable
echo "Listing host data directory permissions and contents after setup:"
ls -ld "${DATA_DIR}/" # Diagnostic
ls -l "${DATA_DIR}/"  # Diagnostic
echo "Target directories ensured."
echo ""

# --- Fetch and Download Quadlet Files ---
echo "Fetching quadlet file list from GitHub (${REPO}, branch: ${BRANCH})..."
# Fetch file list, filter for .container, .network, .volume (excluding sheepvibes-db-volume.volume), and get their download URLs
DOWNLOAD_URLS=$(curl -sSL "${QUADLET_FILES_URL}" | jq -r '.[] | select(.type == "file" and .name != "sheepvibes-db-volume.volume" and (.name | test("\\.(container|network|volume)$"))) | .download_url // empty')

if [ -z "$DOWNLOAD_URLS" ]; then
  echo "No downloadable quadlet files found (after filtering) or error fetching from GitHub repository ${REPO} (branch: ${BRANCH})."
  echo "Please check the repository path, branch name, your internet connection, and ensure relevant files exist in the 'quadlets' directory."
  # For debugging, show the full JSON list from GitHub if DOWNLOAD_URLS is empty
  echo "Raw file list from GitHub:"
  curl -sSL "${QUADLET_FILES_URL}" | jq
  exit 1
fi

echo ""
echo "Downloading quadlet files to ${QUADLET_DIR}..."
SUCCESS_DOWNLOAD=false
for DL_URL in $DOWNLOAD_URLS; do
  # Extract filename from URL
  FILENAME="${DL_URL##*/}"

  echo "Downloading ${FILENAME}..."
  if curl -sSL "${DL_URL}" -o "${QUADLET_DIR}/${FILENAME}"; then
    echo "${FILENAME} downloaded successfully."
    SUCCESS_DOWNLOAD=true
  else
    echo "Error downloading ${FILENAME} from ${DL_URL}."
    # Script will continue trying to download other files.
  fi
done

if ! $SUCCESS_DOWNLOAD; then
    echo ""
    echo "Critical error: No quadlet files were successfully downloaded."
    echo "Please check your internet connection, repository details, and file availability."
    exit 1
fi

# --- User Instructions ---
echo ""
echo "Quadlet files deployed to ${QUADLET_DIR} and data directory ${DATA_DIR} created/ensured."
echo "Please ensure the data directory ${DATA_DIR} is accessible by your user and has appropriate SELinux labels if applicable."
echo ""
echo "Next steps:"
echo "1. Reload systemd to recognize the new/updated unit files:"
echo "   systemctl --user daemon-reload"
echo ""
echo "2. Start the main application service (dependencies will be handled automatically):"
echo "   systemctl --user start sheepvibes-app.service"
echo ""
echo "3. Check the status of the application:"
echo "   systemctl --user status sheepvibes-app.service"
echo "   You can also check other services: systemctl --user status redis.service"
echo ""
echo "4. View logs (follow for real-time updates):"
echo "   journalctl --user -u sheepvibes-app.service -f"
echo ""
echo "To stop the application:"
echo "   systemctl --user stop sheepvibes-app.service"
echo ""
echo "To enable the application to start automatically on boot (for your user):"
echo "   systemctl --user enable sheepvibes-app.service"
echo "   (For this to work at system startup without login, enable lingering for your user: loginctl enable-linger \$(whoami))"
echo ""
echo "Deployment script finished."
