#!/bin/bash

# Script to build (or rebuild) the SheepVibes container image.
# Assumes 'podman' is used.

set -euo pipefail

PRIMARY_IMAGE="localhost/sheepvibes-app:latest"
GHCR_IMAGE="ghcr.io/sheepdestroyer/sheepvibes:latest"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT="$SCRIPT_DIR/.."

echo "--- Building container image ($PRIMARY_IMAGE & $GHCR_IMAGE) ---"

cd "$PROJECT_ROOT" || exit 1
echo "Building image from Containerfile in $(pwd)..."
"$CONTAINER_CMD" build -t "$PRIMARY_IMAGE" -t "$GHCR_IMAGE" -f Containerfile .

echo "--- Build complete for $PRIMARY_IMAGE and $GHCR_IMAGE ---"

if systemctl --user is-active --quiet sheepvibes-app.service 2>/dev/null; then
    echo "--- Restarting systemd user service: sheepvibes-app.service ---"
    systemctl --user restart sheepvibes-app.service
    echo "--- Service successfully restarted ---"
else
    echo "If you are using systemd Quadlet, start/restart the service to apply changes:"
    echo "systemctl --user restart sheepvibes-app.service"
fi

exit 0
