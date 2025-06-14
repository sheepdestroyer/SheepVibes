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
echo "Target directories ensured."
echo ""

# --- Fetch and Download Quadlet Files ---
echo "Fetching quadlet file list from GitHub (${REPO}, branch: ${BRANCH})..."
# Fetch file list, filter for .container, .network, .volume, and get their download URLs
# Handle potential null download_url (though unlikely for actual files)
DOWNLOAD_URLS=$(curl -sSL "${QUADLET_FILES_URL}" | jq -r '.[] | select(.type == "file" and (.name | test("\\.(container|network|volume)$"))) | .download_url // empty')

if [ -z "$DOWNLOAD_URLS" ]; then
  echo "No quadlet files found or error fetching from GitHub repository ${REPO} (branch: ${BRANCH})."
  echo "Please check the repository path, branch name, and your internet connection."
  # Additionally, check if the quadlets directory is empty or if the files don't match the pattern.
  curl -sSL "${QUADLET_FILES_URL}" | jq # Print full JSON for debugging if URLs are empty
  exit 1
fi

echo ""
echo "Downloading quadlet files to ${QUADLET_DIR}..."
SUCCESS_DOWNLOAD=false
for DL_URL in $DOWNLOAD_URLS; do
  # Extract filename from URL (safer than basename for URLs)
  FILENAME="${DL_URL##*/}"
  # Further sanitize filename if necessary, though GitHub URLs should be safe

  echo "Downloading ${FILENAME}..."
  if curl -sSL "${DL_URL}" -o "${QUADLET_DIR}/${FILENAME}"; then
    echo "${FILENAME} downloaded successfully."
    SUCCESS_DOWNLOAD=true
  else
    echo "Error downloading ${FILENAME} from ${DL_URL}."
    # Decide if script should exit on first error or try to download others
    # For now, it will continue, but SUCCESS_DOWNLOAD helps check if anything worked.
  fi
done

if ! $SUCCESS_DOWNLOAD; then
    echo ""
    echo "Critical error: No quadlet files were successfully downloaded."
    echo "Please check your internet connection and the repository details."
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
echo "   You can also check other services: systemctl --user status sheepvibes-redis.service sheepvibes.network"
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
