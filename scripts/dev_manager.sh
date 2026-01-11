#!/bin/bash
set -euo pipefail

# --- Configuration (Overridable via environment variables) ---
readonly POD_NAME="${DEV_POD_NAME:-sheepvibes-dev-pod}"
readonly APP_CONTAINER_NAME="${DEV_APP_CONTAINER:-sheepvibes-dev-app}"
readonly REDIS_CONTAINER_NAME="${DEV_REDIS_CONTAINER:-sheepvibes-dev-redis}"
readonly APP_IMAGE_NAME="${DEV_APP_IMAGE:-localhost/sheepvibes-app}"
readonly REDIS_IMAGE="${DEV_REDIS_IMAGE:-redis:7-alpine}"
readonly REDIS_URL_INTERNAL="${DEV_REDIS_URL_INTERNAL:-redis://localhost:6379/0}"
readonly VOLUME_NAME="${DEV_DATA_VOLUME:-sheepvibes-dev-data}"
readonly CONTAINER_PORT="${DEV_CONTAINER_PORT:-5000}"
readonly DEFAULT_HOST_PORT="${DEV_DEFAULT_HOST_PORT:-5002}"
readonly CMD="${DEV_CMD:-podman}"
readonly BUILD_CONTEXT="${DEV_BUILD_CONTEXT:-.}"
readonly CONTAINERFILE="${DEV_CONTAINERFILE:-Containerfile}"

# Enforce that CMD is a bare executable path without embedded arguments
if [[ "$CMD" =~ [[:space:]] ]]; then
    echo "Error: DEV_CMD must be an executable path without arguments (no whitespace): '$CMD'" >&2
    echo "If you need to pass arguments, wrap them in a wrapper script and set DEV_CMD to that script." >&2
    exit 1
fi

# Robust script directory detection
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR

# Get base command name for display
CMD_BASE="$(basename -- "$CMD")"
readonly CMD_BASE

# --- Functions ---
check_requirements() {
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "Error: '$CMD' is required but not found." >&2
        exit 1
    fi
    
    # Check if the command indicates it is Podman (allows for wrappers/absolute paths)
    if ! "$CMD" --version 2>/dev/null | grep -qi "podman"; then
        echo "Error: This script is Podman-only. '$CMD' does not appear to be Podman." >&2
        exit 1
    fi
}

check_port() {
    local PORT="$1"
    if command -v ss >/dev/null 2>&1; then
        # ss output check: -H (no header), -l (listening), -t (tcp), -n (numeric)
        if ss -Hltn "sport = :$PORT" 2>/dev/null | grep -q "."; then
            return 1
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -i :"$PORT" -sTCP:LISTEN -Fp 2>/dev/null | grep -q '^p'; then
            return 1
        fi
    else
        echo "Error: cannot check port ${PORT}; neither 'ss' nor 'lsof' is available." >&2
        echo "Please install iproute2 (for ss) or lsof and re-run this script." >&2
        exit 1
    fi
    return 0
}

remove_containers() {
    echo "Ensuring containers are removed..."
    # Attempt using --ignore if supported (Podman 4.0+)
    if "$CMD" rm --help 2>&1 | grep -q -w "\-\-ignore"; then
        "$CMD" rm -f --ignore "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME"
    else
        "$CMD" rm -f "$APP_CONTAINER_NAME" "$REDIS_CONTAINER_NAME" 2>/dev/null || true
    fi
}

do_up() {
    local HOST_PORT="${DEFAULT_HOST_PORT}"
    local REBUILD=false
    local PORT_SET=false
    
    while (( $# )); do
        case "$1" in
            --rebuild)
                REBUILD=true
                shift
                ;;
            [0-9]*)
                if [[ "$PORT_SET" == true ]]; then
                    echo "Error: Port argument provided multiple times." >&2
                    usage
                fi
                HOST_PORT="$1"
                PORT_SET=true
                shift
                ;;
            *)
                echo "Error: Unknown argument '$1' for up command." >&2
                usage
                ;;
        esac
    done

    # Validate port format/range
    if ! [[ "${HOST_PORT}" =~ ^[0-9]+$ ]] || (( HOST_PORT < 1 || HOST_PORT > 65535 )); then
        echo "Error: Invalid port '${HOST_PORT}'. Must be an integer between 1 and 65535." >&2
        exit 1
    fi

    # Proactive port check
    if ! check_port "${HOST_PORT}"; then
        echo "Error: Port ${HOST_PORT} is already in use." >&2
        exit 1
    fi

    echo "--- SheepVibes Dev Environment Setup (Runtime: $CMD_BASE) ---"

    # 1. Check/Build Image
    if [[ "$REBUILD" == true ]]; then
        echo "Force rebuild requested. Removing old image if exists..."
        "$CMD" rmi -f "$APP_IMAGE_NAME" 2>/dev/null || true
    fi

    echo "Checking for image $APP_IMAGE_NAME..."
    if ! "$CMD" image exists "$APP_IMAGE_NAME"; then
        echo "Image not found. Building..."
        local PROJECT_ROOT
        PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
        echo "Building image $APP_IMAGE_NAME from $CONTAINERFILE in $PROJECT_ROOT (Context: $BUILD_CONTEXT)..."
        (cd "$PROJECT_ROOT" && "$CMD" build -t "$APP_IMAGE_NAME" -f "$CONTAINERFILE" "$BUILD_CONTEXT")
    else
        echo "Image exists. Skipping build. (Use --rebuild to force rebuild)"
    fi

    # 2. Clean up existing dev pod and leftover containers
    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Existing pod named $POD_NAME found. Removing..."
        "$CMD" pod rm -f "$POD_NAME"
    fi
    
    remove_containers

    # 3. Create Pod and Containers
    echo "Creating pod '$POD_NAME' on port ${HOST_PORT}..."
    "$CMD" pod create --name "$POD_NAME" -p "${HOST_PORT}:${CONTAINER_PORT}"

    echo "Starting Redis ($REDIS_IMAGE)..."
    "$CMD" run -d --pod "$POD_NAME" --name "$REDIS_CONTAINER_NAME" "$REDIS_IMAGE"

    echo "Starting App..."
    "$CMD" run -d --pod "$POD_NAME" --name "$APP_CONTAINER_NAME" \
        -e CACHE_REDIS_URL="$REDIS_URL_INTERNAL" \
        -v "${VOLUME_NAME}:/app/data:Z" \
        "$APP_IMAGE_NAME"

    echo "--- Dev Environment Started ---"
    echo "App URL: http://localhost:${HOST_PORT}"
    echo "To stop: \"$0\" down"
    echo "Logs: $CMD logs $APP_CONTAINER_NAME"
}

do_down() {
    local CLEAN_VOL=false
    
    while (( $# )); do
        case "$1" in
            --clean)
                CLEAN_VOL=true
                shift
                ;;
            *)
                echo "Error: Unknown argument '$1' for down command." >&2
                usage
                ;;
        esac
    done

    echo "--- SheepVibes Dev Environment Teardown (Runtime: $CMD_BASE) ---"

    if "$CMD" pod exists "$POD_NAME" 2>/dev/null; then
        echo "Removing pod $POD_NAME..."
        "$CMD" pod rm -f "$POD_NAME"
        echo "Pod removed."
    else
        echo "Pod $POD_NAME not found."
    fi
    
    remove_containers

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
        echo "Volume $VOLUME_NAME preserved. Use \"$0\" down --clean to remove it."
    fi

    echo "--- Teardown Complete ---"
}

usage() {
    local SCRIPT_NAME
    SCRIPT_NAME="$(basename -- "$0")"
    echo "Usage: \"$SCRIPT_NAME\" {up [port] [--rebuild]|down [--clean]}" >&2
    echo "  up [port] [--rebuild]: Start dev environment (default port: ${DEFAULT_HOST_PORT})" >&2
    echo "                         Use --rebuild to force image rebuild." >&2
    echo "  down [--clean]       : Stop dev environment. Use --clean to delete data volume." >&2
    exit 1
}

# --- Main Dispatch ---
check_requirements

if (( $# < 1 )); then
    usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
    up)
        do_up "$@"
        ;;
    down)
        do_down "$@"
        ;;
    *)
        echo "Error: Unknown command: '$COMMAND'" >&2
        usage
        ;;
esac

