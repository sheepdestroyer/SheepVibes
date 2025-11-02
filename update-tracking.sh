#!/bin/bash

# Script to update the tracking file with new comments
PR_NUMBER="$1"
TRACKING_FILE="pr-review-tracker.json"
COMMENTS_FILE="comments_${PR_NUMBER}.json"

if [ ! -f "$COMMENTS_FILE" ]; then
    echo "Error: Comments file $COMMENTS_FILE not found"
    exit 1
fi

# Extract new comments and add them to tracking file
jq --argjson new_comments "$(jq '[.[] | {id, status: "todo", body, created_at: .submitted_at}]' "$COMMENTS_FILE")" \
   '.branches["feat/unified-pr-tracker"].comments = (.branches["feat/unified-pr-tracker"].comments // []) + $new_comments' \
   "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"

echo "Updated tracking file with new comments from $COMMENTS_FILE"
