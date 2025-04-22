#!/bin/bash

# Script to stop, remove, and rebuild the SheepVibes container image.
# Assumes 'podman' is used. Replace with 'docker' if needed.
# Assumes image name 'sheepvibes-app' and container name 'sheepvibes-instance'.

set -e # Exit immediately if a command exits with a non-zero status.

IMAGE_NAME="sheepvibes-app"
CONTAINER_NAME="sheepvibes-instance"
# Use podman or docker
CONTAINER_CMD="podman" 

# Get the directory where the script resides
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
# Project root is one level up from the scripts directory
PROJECT_ROOT="$SCRIPT_DIR/.."

echo "--- Purging existing container and image ($CONTAINER_NAME / $IMAGE_NAME) ---"

# Check if container exists and stop it
if $CONTAINER_CMD ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "Stopping container $CONTAINER_NAME..."
  $CONTAINER_CMD stop "$CONTAINER_NAME"
else
  echo "Container $CONTAINER_NAME not found, skipping stop."
fi

# Check if container exists (again, could have been stopped but not removed) and remove it
if $CONTAINER_CMD ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "Removing container $CONTAINER_NAME..."
  $CONTAINER_CMD rm "$CONTAINER_NAME"
else
  echo "Container $CONTAINER_NAME not found, skipping remove."
fi

# Check if image exists and remove it
if $CONTAINER_CMD images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}:latest$"; then
  echo "Removing image $IMAGE_NAME:latest..."
  $CONTAINER_CMD rmi "$IMAGE_NAME:latest"
elif $CONTAINER_CMD images --format '{{.Repository}}' | grep -q "^${IMAGE_NAME}$"; then
  # Handle case where image might exist without the 'latest' tag explicitly
  echo "Removing image $IMAGE_NAME (no specific tag)..."
  $CONTAINER_CMD rmi "$IMAGE_NAME"
else
  echo "Image $IMAGE_NAME not found, skipping remove."
fi

echo "--- Building new image ($IMAGE_NAME) ---"

# Build the new image from the project root
cd "$PROJECT_ROOT" || exit 1
echo "Building image $IMAGE_NAME from Containerfile in $(pwd)..."
$CONTAINER_CMD build -t "$IMAGE_NAME" -f Containerfile .

echo "--- Rebuild complete for image $IMAGE_NAME ---"
echo "You can now run the container using './scripts/manage_container.sh start' or manually, e.g.:"
echo "$CONTAINER_CMD run -d --name $CONTAINER_NAME -p 5000:5000 -v sheepvibes-data:/app/data --restart unless-stopped $IMAGE_NAME"

exit 0
