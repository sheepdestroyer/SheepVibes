#!/bin/bash

# Script to trigger Google Code Assist review by posting /gemini review comment
# Usage: ./trigger-review.sh [pr-number]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub API configuration
GITHUB_API="https://api.github.com"

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"

# Get repository owner and name
get_repo_info

# Check dependencies
check_dependencies

# Check if GITHUB_TOKEN is set
if [ -z "${GITHUB_TOKEN:-}" ]; then
    printf "${RED}Error: GITHUB_TOKEN environment variable is not set${NC}\n" >&2
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
    printf "${RED}Error: PR number must be numeric${NC}\n" >&2
    exit 1
fi

printf "${YELLOW}Triggering Google Code Assist review for PR #$PR_NUMBER...${NC}\n"

# Post /gemini review comment
data='{"body": "/gemini review"}'
if github_api_request "/issues/$PR_NUMBER/comments" "POST" "$data" > /dev/null; then
    printf "${GREEN}Successfully posted /gemini review comment to PR #$PR_NUMBER${NC}\n"
else
    printf "${RED}Failed to post comment to PR #$PR_NUMBER${NC}\n" >&2
    exit 1
fi

printf "${GREEN}Google Code Assist review has been triggered.${NC}\n"
