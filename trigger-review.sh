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
Usage: $0 [pr-number]

Triggers a Google Code Assist review by posting a "/gemini review" comment to the specified PR.

Example:
  $0 162
EOF
}

# Parse command line arguments
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

PR_NUMBER="$1"

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

echo -e "${GREEN}Google Code Assist review has been triggered.${NC}"
