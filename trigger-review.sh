#!/bin/bash

# Script to trigger Google Code Assist review by posting /gemini review comment
# and optionally wait for completion
# Usage: ./trigger-review.sh [pr-number] [--wait]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub API configuration
GITHUB_API="https://api.github.com"
REPO="${GITHUB_REPO:-sheepdestroyer/SheepVibes}"

# Check if GITHUB_TOKEN is set
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo -e "${RED}Error: GITHUB_TOKEN environment variable is not set${NC}" >&2
    exit 1
fi

usage() {
    cat << EOF
Usage: $0 [pr-number] [--wait]

Triggers Google Code Assist review by posting "/gemini review" comment to a PR.

Options:
  --wait    Wait for review completion and check status

Example:
  $0 162
  $0 162 --wait
EOF
}

# Parse command line arguments
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    usage
    exit 1
fi

PR_NUMBER="$1"
WAIT_FOR_REVIEW=false

if [ $# -eq 2 ] && [ "$2" = "--wait" ]; then
    WAIT_FOR_REVIEW=true
fi

# Validate PR number is numeric
if ! [[ "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: PR number must be numeric${NC}" >&2
    exit 1
fi

echo -e "${YELLOW}Triggering Google Code Assist review for PR #$PR_NUMBER...${NC}"

# Post /gemini review comment
response=$(curl -s -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Content-Type: application/json" \
    -d '{"body": "/gemini review"}' \
    "$GITHUB_API/repos/$REPO/issues/$PR_NUMBER/comments")

# Check if the request was successful
if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
    echo -e "${GREEN}Successfully posted /gemini review comment to PR #$PR_NUMBER${NC}"
else
    echo -e "${RED}Failed to post comment to PR #$PR_NUMBER${NC}" >&2
    echo "Response: $response" >&2
    exit 1
fi

# If wait flag is set, wait for review completion
if [ "$WAIT_FOR_REVIEW" = true ]; then
    echo -e "${BLUE}Waiting for Google Code Assist review to complete...${NC}"
    
    # Wait for initial review (5 minutes maximum)
    local max_wait=300  # 5 minutes
    local wait_interval=30  # 30 seconds
    local elapsed=0
    
    while [ $elapsed -lt $max_wait ]; do
        sleep $wait_interval
        elapsed=$((elapsed + wait_interval))
        
        # Check review status using the check-review-status script
        echo -e "${BLUE}Checking review status... (${elapsed}s elapsed)${NC}"
        review_status=$(bash check-review-status.sh "$PR_NUMBER" 2>/dev/null | grep -E "^(None|Started|Commented)$" | head -1)
        
        if [ "$review_status" = "Commented" ]; then
            echo -e "${GREEN}Google Code Assist review completed with comments${NC}"
            exit 0
        elif [ "$review_status" = "None" ]; then
            echo -e "${GREEN}Google Code Assist review completed - no issues found${NC}"
            exit 0
        fi
    done
    
    echo -e "${YELLOW}Google Code Assist review did not complete within ${max_wait}s timeout${NC}"
    exit 1
else
    echo -e "${GREEN}Google Code Assist review has been triggered. Use './trigger-review.sh $PR_NUMBER --wait' to wait for completion.${NC}"
fi
