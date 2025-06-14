#!/bin/bash

# Exit immediately if a command exits with a non-zero status, 
# try to use an undefined variable, 
# and the pipeline's exit code is the exit code of the rightmost command to fail, 
# or zero if all succeed.
set -euo pipefail

# --- Configuration ---
REPO="sheepdestroyer/sheepvibes"
BRANCH="main" # Or specify a tag/commit if preferred
QUADLET_DIR="${HOME}/.config/containers/systemd"
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
echo "--- Cleaning up old SheepVibes quadlet files ---"
if [ -d "${QUADLET_DIR}" ]; then
    echo "Found quadlet directory at ${QUADLET_DIR}."
    # Find files matching the sheepvibes-* pattern and remove them.
    # The 'find' command is used for safety and to handle cases where no files exist.
    # -maxdepth 1 ensures we only search in the top-level directory.
    find "${QUADLET_DIR}" -maxdepth 1 -name 'sheepvibes-*.container' -o -name 'sheepvibes-*.volume' -o -name 'sheepvibes-*.network' | while read -r file; do
        if [ -f "$file" ]; then
            echo "Removing old file: $file"
            rm -f "$file"
        fi
    done
    echo "Cleanup complete."
else
    echo "No existing quadlet directory found. Skipping cleanup."
fi
echo ""

# --- Fetch and Download Quadlet Files ---
echo "Fetching quadlet file list from GitHub (${REPO}, branch: ${BRANCH})..."
# Modified to fetch all .container, .network, and .volume files.
DOWNLOAD_URLS=$(curl -sSL "${QUADLET_FILES_URL}" | jq -r '.[] | select(.type == "file" and (.name | test("\\.(container|network|volume)$"))) | .download_url // empty')

if [ -z "$DOWNLOAD_URLS" ]; then
  echo "No downloadable quadlet files found or error fetching from GitHub repository ${REPO} (branch: ${BRANCH})."
  echo "Please check the repository path, branch name, and your internet connection."
  exit 1
fi

echo ""
echo "Downloading quadlet files to ${QUADLET_DIR}..."
SUCCESS_DOWNLOAD=false
for DL_URL in $DOWNLOAD_URLS; do
  FILENAME="${DL_URL##*/}"
  echo "Downloading ${FILENAME}..."
  if curl -sSL "${DL_URL}" -o "${QUADLET_DIR}/${FILENAME}"; then
    echo "${FILENAME} downloaded successfully."
    SUCCESS_DOWNLOAD=true
  else
    echo "Error downloading ${FILENAME} from ${DL_URL}."
  fi
done

if ! $SUCCESS_DOWNLOAD; then
    echo ""
    echo "Critical error: No quadlet files were successfully downloaded."
    exit 1
fi

# --- User Instructions ---
echo ""
echo "Quadlet files deployed to ${QUADLET_DIR}."
echo "The application will use a Podman-managed volume named 'sheepvibes-db' for database persistence."
echo ""
echo "Next steps:"
echo "1. Reload systemd to recognize the new/updated unit files:"
echo "   systemctl --user daemon-reload && systemctl --user list-unit-files 'sheepvibes*'"
echo ""
echo "2. Start the main application service (dependencies will be handled automatically):"
echo "   systemctl --user start sheepvibes-app.service"
echo ""
echo "3. Check the status of the application:"
echo "   systemctl --user status sheepvibes-app.service"
echo "   You can inspect the auto-created volume with: podman volume inspect sheepvibes-db"
echo ""
echo "4. View logs (follow for real-time updates):"
echo "   journalctl --user -u sheepvibes-app.service -f"
echo ""
echo "To stop the application:"
echo "   systemctl --user stop sheepvibes-app.service"
echo ""
echo "To enable the application to start automatically when you log in:"
echo "   systemctl --user enable sheepvibes-app.service"
echo ""
echo "Deployment script finished."
