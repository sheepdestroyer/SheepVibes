#!/bin/bash
set -euo pipefail

# --- Configuration (Overridable via environment variables) ---
readonly POD_NAME="${DEV_POD_NAME:-sheepvibes-dev-pod}"
readonly APP_CONTAINER_NAME="${DEV_APP_CONTAINER:-sheepvibes-dev-app}"
readonly REDIS_CONTAINER_NAME="${DEV_REDIS_CONTAINER:-sheepvibes-dev-redis}"
readonly APP_IMAGE_NAME="${DEV_APP_IMAGE:-localhost/sheepvibes-app}"
readonly REDIS_IMAGE="${DEV_REDIS_IMAGE:-redis:alpine}"
readonly VOLUME_NAME="${DEV_DATA_VOLUME:-sheepvibes-dev-data}"
readonly CONTAINER_PORT="${DEV_CONTAINER_PORT:-5000}"
readonly CMD="${DEV_CMD:-podman}"
readonly BUILD_CONTEXT="${DEV_BUILD_CONTEXT:-.}"
readonly CONTAINERFILE="${DEV_CONTAINERFILE:-Containerfile}"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
readonly SCRIPT_DIR

# --- Functions ---
check_requirements() {
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "Error: '$CMD' is required but not found." >&2
        exit 1
    fi
    
    if [[ "$CMD" != "podman" ]]; then
        echo "Error: This script is Podman-only. Found: $CMD" >&2
        exit 1
    fi
}

check_port() {
    local PORT="$1"
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :$PORT" 2>/dev/null | tail -n +2 | grep -q .; then
            return 1
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -i :"$PORT" -sTCP:LISTEN -Fp 2>/dev/null | grep -q '^p'; then
            return 1
        fi
    fi
    return 0
}

do_up() {
    local HOST_PORT="${1:-5002}"
    
    # Validate port format/range
    if ! [[ "$HOST_PORT" =~ ^[0-9]+$ ]] || (( HOST_PORT < 1 || HOST_PORT > 65535 )); then
        echo "Error: Invalid port '$HOST_PORT'. Must be an integer between 1 and 65535." >&2
        exit 1
    fi

    # Proactive port check
    if ! check_port "$HOST_PORT"; then
        echo "Error: Port $HOST_PORT is already in use." >&2
        exit 1
    fi

    echo "--- SheepVibes Dev Environment Setup (Runtime: $CMD) ---"

    # 1. Check/Build Image
    echo "Checking for image $APP_IMAGE_NAME..."
    if ! "$CMD" image exists "$APP_IMAGE_NAME"; then
        echo "Image not found. Building..."
        local PROJECT_ROOT
        PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
        echo "Building image $APP_IMAGE_NAME from $CONTAINERFILE in $PROJECT_ROOT (Context: $BUILD_CONTEXT)..."
        if ! (cd "$PROJECT_ROOT" && "$CMD" build -t "$APP_IMAGE_NAME" -f "$CONTAINERFILE" "$BUILD_CONTEXT"); then
            echo "Error: Image build failed." >&2
            exit 1
        fi
    else
        echo "Image exists. Skipping build. (Run scripts/rebuild_container.sh explicitly to rebuild)"
    fi

    # 2. Clean up existing dev pod and leftover containers
    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Existing pod named $POD_NAME found. Removing..."
        "$CMD" pod rm -f "$POD_NAME"
    fi
    
    # Ensure containers are also gone (robust cleanup)
    echo "Ensuring no stale containers exist..."
    # Attempt using --ignore if supported (Podman 4.0+)
    if "$CMD" rm --help | grep -q "\-\-ignore"; then
        "$CMD" rm -f --ignore "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME"
    else
        "$CMD" rm -f "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME" 2>/dev/null || true
    fi

    # 3. Create Pod and Containers
    echo "Creating pod '$POD_NAME' on port $HOST_PORT..."
    "$CMD" pod create --name "$POD_NAME" -p "${HOST_PORT}:${CONTAINER_PORT}"

    echo "Starting Redis..."
    "$CMD" run -d --pod "$POD_NAME" --name "$REDIS_CONTAINER_NAME" "$REDIS_IMAGE"

    echo "Starting App..."
    "$CMD" run -d --pod "$POD_NAME" --name "$APP_CONTAINER_NAME" \
        -e CACHE_REDIS_URL="redis://localhost:6379/0" \
        -v "${VOLUME_NAME}:/app/data:Z" \
        "$APP_IMAGE_NAME"

    echo "--- Dev Environment Started ---"
    echo "App URL: http://localhost:$HOST_PORT"
    echo "To stop: $0 down"
    echo "Logs: $CMD logs $APP_CONTAINER_NAME"
}

do_down() {
    local CLEAN_VOL=false
    local FLAG="${1:-}"
    
    if [[ -n "$FLAG" ]]; then
        if [[ "$FLAG" == "--clean" ]]; then
            CLEAN_VOL=true
        else
            echo "Error: Unknown flag '$FLAG'. Usage: $0 down [--clean]" >&2
            exit 1
        fi
    fi

    echo "--- SheepVibes Dev Environment Teardown (Runtime: $CMD) ---"

    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Removing pod $POD_NAME..."
        "$CMD" pod rm -f "$POD_NAME"
        echo "Pod removed."
    else
        echo "Pod $POD_NAME not found."
    fi
    
    # Mirror robust cleanup from do_up
    echo "Ensuring all containers are removed..."
    if "$CMD" rm --help | grep -q "\-\-ignore"; then
        "$CMD" rm -f --ignore "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME"
    else
        "$CMD" rm -f "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME" 2>/dev/null || true
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
    echo "Usage: $0 {up [port]|down [--clean]}" >&2
    echo "  up [port]    : Start dev environment (default port: 5002)" >&2
    echo "  down [--clean]: Stop dev environment. Use --clean to delete data volume." >&2
    exit 1
}

# --- Main Dispatch ---
check_requirements

case "${1:-}" in
    up)
        if (( $# > 2 )); then usage; fi
        do_up "${2:-}"
        ;;
    down)
        if (( $# > 2 )); then usage; fi
        do_down "${2:-}"
        ;;
    *)
        usage
        ;;
esac

