#!/bin/bash
set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/common.sh"

# Check for required arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <pr_number> <branch_name>"
    exit 1
fi

PR_NUMBER="$1"
BRANCH_NAME="$2"
TRACKING_FILE="pr-review-tracker.json"
LOCK_FILE="${TRACKING_FILE}.lock"

# Check if tracking file exists, create if not
if [ ! -f "$TRACKING_FILE" ]; then
    echo '{"branches": {}, "last_updated": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}' > "$TRACKING_FILE"
fi

# Check if comments file exists
COMMENTS_FILE="comments_${PR_NUMBER}.json"
if [ ! -f "$COMMENTS_FILE" ]; then
    echo "Error: Comments file $COMMENTS_FILE not found. Run check-review-status.sh first." >&2
    exit 1
fi

# Use file locking to prevent concurrent modifications
(
    flock -x 200 || exit 1

    echo "Updating tracking file with comments from $COMMENTS_FILE for branch $BRANCH_NAME..."

    # Use slurpfile to read all comments at once, avoiding ARG_MAX issues
    # and process them in a single jq invocation for efficiency.
    jq --arg branch "$BRANCH_NAME" \
       --arg pr_num "$PR_NUMBER" \
       --arg updated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
       --slurpfile new_comments_raw "$COMMENTS_FILE" '
        # Create the list of new comments with the correct structure
        ( $new_comments_raw[0] | map({id, status: "todo", body, created_at: .submitted_at}) ) as $new_comments |
        # Initialize branch if it does not exist
        (.branches[$branch]) |= (
            . // {pr_number: ($pr_num | tonumber), review_status: "Commented", comments: []}
        ) |
        # Merge new comments and ensure they are unique
        .branches[$branch].comments |= ( . + $new_comments | unique_by(.id) ) |
        # Update timestamps
        .branches[$branch].last_updated = $updated |
        .last_updated = $updated
    ' "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"

    echo "Updated tracking file with new comments from $COMMENTS_FILE for branch $BRANCH_NAME"
) 200>"$LOCK_FILE"

