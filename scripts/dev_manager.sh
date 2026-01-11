#!/bin/bash
set -e

# --- Configuration ---
POD_NAME="sheepvibes-dev-pod"
APP_CONTAINER_NAME="sheepvibes-dev-app"
REDIS_CONTAINER_NAME="sheepvibes-dev-redis"
APP_IMAGE_NAME="localhost/sheepvibes-app"
REDIS_IMAGE="redis:alpine"
VOLUME_NAME="sheepvibes-dev-data"
CONTAINER_PORT="5000"

# --- Functions ---
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

get_runtime() {
    if command_exists podman; then
        echo "podman"
    elif command_exists docker; then
        echo "docker"
    else
        echo "Error: Neither podman nor docker found. Please install one." >&2
        exit 1
    fi
}

CMD=$(get_runtime)

do_up() {
    HOST_PORT="${1:-5002}"
    
    echo "--- SheepVibes Dev Environment Setup (Runtime: $CMD) ---"

    # 1. Check/Build Image
    echo "Checking for image $APP_IMAGE_NAME..."
    if ! $CMD image exists "$APP_IMAGE_NAME"; then
        echo "Image not found. Building..."
        SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
        "$SCRIPT_DIR/rebuild_container.sh"
    else
        echo "Image exists. Skipping build. (Run scripts/rebuild_container.sh explicitly to rebuild)"
    fi

    # 2. Clean up existing dev pod
    if $CMD pod exists "$POD_NAME" 2>/dev/null;
 then
        echo "Existing pod named $POD_NAME found. Removing..."
        $CMD pod rm -f "$POD_NAME"
    fi

    # 3. Create Pod and Containers
    echo "Creating pod '$POD_NAME' on port $HOST_PORT..."
    $CMD pod create --name "$POD_NAME" -p "${HOST_PORT}:${CONTAINER_PORT}"

    echo "Starting Redis..."
    $CMD run -d --pod "$POD_NAME" --name "$REDIS_CONTAINER_NAME" "$REDIS_IMAGE"

    echo "Starting App..."
    $CMD run -d --pod "$POD_NAME" --name "$APP_CONTAINER_NAME" \
        -e CACHE_REDIS_URL="redis://localhost:6379/0" \
        -v "${VOLUME_NAME}:/app/data" \
        "$APP_IMAGE_NAME"

    echo "--- Dev Environment Started ---"
    echo "App URL: http://localhost:$HOST_PORT"
    echo "To stop: $0 down"
    echo "Logs: $CMD logs $APP_CONTAINER_NAME"
}

do_down() {
    CLEAN_VOL=false
    if [ "$1" == "--clean" ]; then
        CLEAN_VOL=true
    fi

    echo "--- SheepVibes Dev Environment Teardown (Runtime: $CMD) ---"

    if $CMD pod exists "$POD_NAME" 2>/dev/null;
 then
        echo "Removing pod $POD_NAME..."
        $CMD pod rm -f "$POD_NAME"
        echo "Pod removed."
    else
        echo "Pod $POD_NAME not found."
    fi

    # Cleanup Volume
    if [ "$CLEAN_VOL" = true ]; then
        echo "Removing volume $VOLUME_NAME..."
        if $CMD volume exists "$VOLUME_NAME" 2>/dev/null;
 then
            $CMD volume rm "$VOLUME_NAME"
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
case "$1" in
    up)
        do_up "$2"
        ;;
    down)
        do_down "$2"
        ;;
    *)
        usage
        ;;
esac
