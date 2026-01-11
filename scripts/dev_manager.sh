#!/bin/bash
set -euo pipefail

# --- Configuration ---
readonly POD_NAME="sheepvibes-dev-pod"
readonly APP_CONTAINER_NAME="sheepvibes-dev-app"
readonly REDIS_CONTAINER_NAME="sheepvibes-dev-redis"
readonly APP_IMAGE_NAME="localhost/sheepvibes-app"
readonly REDIS_IMAGE="redis:alpine"
readonly VOLUME_NAME="sheepvibes-dev-data"
readonly CONTAINER_PORT="5000"
readonly CMD="podman"

# --- Functions ---
check_requirements() {
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "Error: 'podman' is required but not found." >&2
        exit 1
    fi
}

do_up() {
    local HOST_PORT="${1:-5002}"
    
    # Validate port
    if ! [[ "$HOST_PORT" =~ ^[0-9]+$ ]] || (( HOST_PORT < 1 || HOST_PORT > 65535 )); then
        echo "Error: Invalid port '$HOST_PORT'. Must be an integer between 1 and 65535." >&2
        exit 1
    fi

    echo "--- SheepVibes Dev Environment Setup (Runtime: $CMD) ---"

    # 1. Check/Build Image
    echo "Checking for image $APP_IMAGE_NAME..."
    if ! "$CMD" image exists "$APP_IMAGE_NAME"; then
        echo "Image not found. Building..."
        local SCRIPT_DIR
        SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
        local REBUILD_SCRIPT="$SCRIPT_DIR/rebuild_container.sh"
        
        if [[ ! -x "$REBUILD_SCRIPT" ]]; then
            echo "Error: Rebuild script not found or not executable at $REBUILD_SCRIPT" >&2
            exit 1
        fi
        
        "$REBUILD_SCRIPT"
    else
        echo "Image exists. Skipping build. (Run scripts/rebuild_container.sh explicitly to rebuild)"
    fi

    # 2. Clean up existing dev pod
    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Existing pod named $POD_NAME found. Removing..."
        "$CMD" pod rm -f "$POD_NAME"
    fi

    # 3. Create Pod and Containers
    echo "Creating pod '$POD_NAME' on port $HOST_PORT..."
    "$CMD" pod create --name "$POD_NAME" -p "${HOST_PORT}:${CONTAINER_PORT}"

    echo "Starting Redis..."
    "$CMD" run -d --pod "$POD_NAME" --name "$REDIS_CONTAINER_NAME" "$REDIS_IMAGE"

    echo "Starting App..."
    "$CMD" run -d --pod "$POD_NAME" --name "$APP_CONTAINER_NAME" \
        -e CACHE_REDIS_URL="redis://localhost:6379/0" \
        -v "${VOLUME_NAME}:/app/data" \
        "$APP_IMAGE_NAME"

    echo "--- Dev Environment Started ---"
    echo "App URL: http://localhost:$HOST_PORT"
    echo "To stop: $0 down"
    echo "Logs: $CMD logs $APP_CONTAINER_NAME"
}

do_down() {
    local CLEAN_VOL=false
    if [[ "${1:-}" == "--clean" ]]; then
        CLEAN_VOL=true
    fi

    echo "--- SheepVibes Dev Environment Teardown (Runtime: $CMD) ---"

    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Removing pod $POD_NAME..."
        "$CMD" pod rm -f "$POD_NAME"
        echo "Pod removed."
    else
        echo "Pod $POD_NAME not found."
    fi

    # Cleanup Volume
    if [[ "$CLEAN_VOL" == true ]]; then
        echo "Removing volume $VOLUME_NAME..."
        if "$CMD" volume exists "$VOLUME_NAME" 2>/dev/null; then
            "$CMD" volume rm "$VOLUME_NAME"
            echo "Volume removed."
        else
            echo "Volume $VOLUME_NAME not found."
        fi
    else
        echo "Volume $VOLUME_NAME preserved. Use '$0 down --clean' to remove it."
    fi

    echo "--- Teardown Complete ---"
}

usage() {
    echo "Usage: $0 {up [port]|down [--clean]}"
    echo "  up [port]    : Start dev environment (default port: 5002)"
    echo "  down [--clean]: Stop dev environment. Use --clean to delete data volume."
    exit 1
}

# --- Main Dispatch ---
check_requirements

case "${1:-}" in
    up)
        do_up "${2:-}"
        ;;
    down)
        do_down "${2:-}"
        ;;
    *)
        usage
        ;;
esac

