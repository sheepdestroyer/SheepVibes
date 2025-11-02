
#!/bin/bash

# Script to mark specific comments as addressed
TRACKING_FILE="pr-review-tracker.json"

# Update the three comments we just addressed
jq '(.branches["feat/unified-pr-tracker"].comments[] | select(.id == 2484165711 or .id == 2484165712 or .id == 2484165713) | .status) = "addressed"' "$TRACKING_FILE" > "${TRACKING_FILE}.tmp" && mv "${TRACKING_FILE}.tmp" "$TRACKING_FILE"

echo "Marked comments 2484165711, 2484165712, 2484165713 as addressed"

