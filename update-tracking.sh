#!/bin/bash

# Script to update the tracking file with new comments
# Usage: ./update-tracking.sh <pr-number> <branch-name>

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <pr-number> <branch-name>"
    echo "Example: $0 162 feat/unified-pr-tracker"
    exit 1
fi

PR_NUMBER="$1"
BRANCH_NAME="$2"
TRACKING_FILE="pr-review-tracker.json"
COMMENTS_FILE="comments_${PR_NUMBER}.json"
LOCK_FILE="${TRACKING_FILE}.lock"

# Source common functions and variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/common.sh"

if [ ! -f "$COMMENTS_FILE" ]; then
    echo "Error: Comments file $COMMENTS_FILE not found"
    exit 1
fi

# Use file locking to prevent concurrent modifications
(
    flock -x 200 || exit 1
    
    # Extract new comments and add them to tracking file with deduplication
    jq --arg branch "$BRANCH_NAME" --argjson new_comments "$(jq '[.[] | {id, status: "todo", body, created_at: .submitted_at}]' "$COMMENTS_FILE")" \
       '.branches[$branch].comments = ((.branches[$branch].comments // []) + $new_comments) | unique_by(.id)' \
       "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"
    
    echo "Updated tracking file with new comments from $COMMENTS_FILE for branch $BRANCH_NAME"
) 200>"$LOCK_FILE"
