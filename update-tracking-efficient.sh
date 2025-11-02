#!/bin/bash
set -e

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

    # Process comments in smaller batches to avoid argument limits
    jq -c '.[]' "$COMMENTS_FILE" | while IFS= read -r comment; do
        jq --arg branch "$BRANCH_NAME" --argjson comment "$comment" '
            if .branches[$branch] == null then
                .branches[$branch] = {
                    pr_number: '"$PR_NUMBER"',
                    review_status: "Commented",
                    last_updated: "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
                    comments: []
                }
            else
                .
            end |
            .branches[$branch].comments |= (
                . + [$comment] | unique_by(.id)
            ) |
            .last_updated = "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
        ' "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"
    done

    echo "Updated tracking file with new comments from $COMMENTS_FILE for branch $BRANCH_NAME"
) 200>"$LOCK_FILE"

