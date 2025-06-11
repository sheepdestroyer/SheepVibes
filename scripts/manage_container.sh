#!/bin/bash

# Script to manage the SheepVibes container (start, stop, restart).
# Assumes 'podman' is used. Replace with 'docker' if needed.

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
IMAGE_NAME="sheepvibes-app"
CONTAINER_NAME="sheepvibes-instance"
VOLUME_NAME="sheepvibes-data"
HOST_PORT="5000"
CONTAINER_PORT="5000"
DATA_PATH="/app/data" # Updated data path inside the container
RESTART_POLICY="unless-stopped"
# Use podman or docker
CONTAINER_CMD="podman"
# --- End Configuration ---

# Function to check if container exists
container_exists() {
  $CONTAINER_CMD ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Function to check if container is running
container_is_running() {
  $CONTAINER_CMD ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# --- Command Logic ---
start_container() {
  echo "--- Starting container $CONTAINER_NAME ---"
  if container_exists; then
    if container_is_running; then
      echo "Container $CONTAINER_NAME is already running."
    else
      echo "Container $CONTAINER_NAME exists but is stopped. Starting..."
      $CONTAINER_CMD start "$CONTAINER_NAME"
      echo "Container $CONTAINER_NAME started."
    fi
  else
    echo "Container $CONTAINER_NAME does not exist. Creating and starting..."
    # Check if volume exists, create if not
    if ! $CONTAINER_CMD volume inspect "$VOLUME_NAME" &> /dev/null; then
        echo "Volume $VOLUME_NAME not found. Creating..."
        $CONTAINER_CMD volume create "$VOLUME_NAME"
    fi
    
    $CONTAINER_CMD run \
      -d \
      --name "$CONTAINER_NAME" \
      -p "127.0.0.1:${HOST_PORT}:${CONTAINER_PORT}" \
      -v "${VOLUME_NAME}:${DATA_PATH}" \
      --restart "$RESTART_POLICY" \
      --replace \
      "$IMAGE_NAME"
    echo "Container $CONTAINER_NAME created and started."
  fi
}

stop_container() {
  echo "--- Stopping container $CONTAINER_NAME ---"
  if container_is_running; then
    echo "Stopping container $CONTAINER_NAME..."
    $CONTAINER_CMD stop "$CONTAINER_NAME"
    echo "Container $CONTAINER_NAME stopped."
  elif container_exists; then
    echo "Container $CONTAINER_NAME exists but is already stopped."
  else
    echo "Container $CONTAINER_NAME not found. Cannot stop."
  fi
}

restart_container() {
  echo "--- Restarting container $CONTAINER_NAME ---"
  # Explicitly stop and then start for more robust handling
  stop_container
  start_container
}

# --- Main Script ---
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 {start|stop|restart}"
  exit 1
fi

COMMAND=$1

case "$COMMAND" in
  start)
    start_container
    ;;
  stop)
    stop_container
    ;;
  restart)
    restart_container
    ;;
  *)
    echo "Invalid command: $COMMAND"
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac

exit 0
