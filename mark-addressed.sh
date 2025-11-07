
#!/bin/bash

# Script to mark specific comments as addressed
# Usage: ./mark-addressed.sh <branch-name> <comment-id1> [comment-id2] [comment-id3] ...

set -euo pipefail

TRACKING_FILE="pr-review-tracker.json"
LOCK_FILE="${TRACKING_FILE}.lock"

# Source common functions and variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/common.sh"

# Check for required arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <branch-name> <comment-id1> [comment-id2] [comment-id3] ..."
    echo "Example: $0 feat/unified-pr-tracker 2484165711 2484165712 2484165713"
    exit 1
fi

BRANCH_NAME="$1"
shift
COMMENT_IDS=("$@")

# Build a JSON array of comment IDs to pass to jq safely
COMMENT_ID_ARRAY=$(printf '%s\n' "${COMMENT_IDS[@]}" | jq -R . | jq -s 'map(tonumber)')

# Use file locking to prevent concurrent modifications
(
    flock -x 200 || exit 1
    
    # Update the specified comments as addressed
    jq --arg branch "$BRANCH_NAME" --argjson ids "$COMMENT_ID_ARRAY" --arg updated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
       '.last_updated = $updated | .branches[$branch]? |= (.last_updated = $updated | .comments? |= map(if .id | inside($ids) then .status = "addressed" else . end))' \
       "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"
    
    echo "Marked comments ${COMMENT_IDS[*]} as addressed for branch $BRANCH_NAME"
) 200>"$LOCK_FILE"

