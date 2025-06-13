#!/bin/bash

# Script to build (or rebuild) the SheepVibes container image.
# Assumes 'podman' is used. Replace with 'docker' if needed.
# Assumes the local image will be named 'sheepvibes-app'.

set -e # Exit immediately if a command exits with a non-zero status.

IMAGE_NAME="localhost/sheepvibes-app"
# Use podman or docker
CONTAINER_CMD="podman" 

# Get the directory where the script resides
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
# Project root is one level up from the scripts directory
PROJECT_ROOT="$SCRIPT_DIR/.."

echo "--- Building new image ($IMAGE_NAME) ---"

# Build the new image from the project root
cd "$PROJECT_ROOT" || exit 1
echo "Building image $IMAGE_NAME from Containerfile in $(pwd)..."
$CONTAINER_CMD build -t "$IMAGE_NAME" -f Containerfile .

echo "--- Build complete for image $IMAGE_NAME ---"
echo "If you are using systemd, restart the service to apply changes:"
echo "systemctl --user restart sheepvibes-app.service"

exit 0
