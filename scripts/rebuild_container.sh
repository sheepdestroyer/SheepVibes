#!/bin/bash

# Script to build (or rebuild) the SheepVibes container image for local development.
# Assumes 'podman' is used.

set -euo pipefail

IMAGE_NAME="localhost/sheepvibes-app:latest"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT="$SCRIPT_DIR/.."

echo "--- Building local development image ($IMAGE_NAME) ---"

cd "$PROJECT_ROOT" || exit 1
echo "Building image from Containerfile in $(pwd)..."
"$CONTAINER_CMD" build -t "$IMAGE_NAME" -f Containerfile .

echo "--- Build complete for $IMAGE_NAME ---"
echo "Note: Production deployments pull from ghcr.io via GitHub Actions tags (v*.*)."

exit 0
