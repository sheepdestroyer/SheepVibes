#!/bin/bash

# set-pr-ready.sh - Script to ensure PRs are marked as "Ready for review" using GitHub API
# Usage: ./set-pr-ready.sh [pr-number] [--force]

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

# Check if GITHUB_TOKEN is set
if [ -z "${GITHUB_TOKEN:-}" ]; then
    printf "${RED}Error: GITHUB_TOKEN environment variable is not set${NC}\n" >&2
    exit 1
fi

usage() {
    cat << EOF
Usage: $0 [pr-number] [--force]

Ensures that a pull request is marked as "Ready for review" (not draft).

If the PR is currently a draft, this script will mark it as ready for review.
If the PR is already ready for review, no action is taken.

Options:
  --force    Force the PR to be marked as ready even if it's already ready

Examples:
  $0 162          # Mark PR #162 as ready for review if it's a draft
  $0 162 --force  # Force mark PR #162 as ready for review

Exit Codes:
  0 - Success
  1 - Error occurred
  2 - PR not found or access denied
EOF
}

# Function to make GitHub API request
github_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local url="${GITHUB_API}/repos/${REPO_OWNER}/${REPO_NAME}${endpoint}"
    
    local curl_cmd=("curl" "-s" "-X" "$method")
    
    curl_cmd+=("-H" "Authorization: token $GITHUB_TOKEN")
    curl_cmd+=("-H" "Accept: application/vnd.github.v3+json")
    
    if [ -n "$data" ]; then
        curl_cmd+=("-H" "Content-Type: application/json")
        curl_cmd+=("-d" "$data")
    fi
    
    curl_cmd+=("$url")
    
    "${curl_cmd[@]}"
}

# Function to get PR details
get_pr_details() {
    local pr_number="$1"
    github_api_request "GET" "/pulls/${pr_number}" ""
}

# Function to mark PR as ready for review
mark_pr_ready() {
    local pr_number="$1"
    printf "${BLUE}Marking PR #${pr_number} as ready for review...${NC}\n"
    
    response=$(github_api_request "PATCH" "/pulls/${pr_number}" '{"draft":false}')
    
    if echo "$response" | jq -e '.id' > /dev/null 2>&1; then
        printf "${GREEN}Successfully marked PR #${pr_number} as ready for review${NC}\n"
        return 0
    else
        printf "${RED}Failed to mark PR #${pr_number} as ready for review${NC}\n" >&2
        printf "Response: %s\n" "$response" >&2
        return 1
    fi
}

# Main function
main() {
    local pr_number=""
    local force=false
    
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --force)
                force=true
                shift
                ;;
            *)
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    pr_number="$1"
                    shift
                else
                    printf "${RED}Error: Invalid argument '$1'${NC}\n" >&2
                    usage
                    exit 1
                fi
                ;;
        esac
    done
    
    if [ -z "$pr_number" ]; then
        printf "${RED}Error: PR number is required${NC}\n" >&2
        usage
        exit 1
    fi
    
    printf "${BLUE}Checking status of PR #${pr_number}...${NC}\n"
    
    # Get PR details
    pr_details=$(get_pr_details "$pr_number")
    
    # Check if PR exists and we have access
    if echo "$pr_details" | jq -e '.message' > /dev/null 2>&1; then
        local error_message=$(echo "$pr_details" | jq -r '.message')
        printf "${RED}Error accessing PR #${pr_number}: ${error_message}${NC}\n" >&2
        exit 2
    fi
    
    # Extract PR information
    local pr_title=$(echo "$pr_details" | jq -r '.title')
    local is_draft=$(echo "$pr_details" | jq -r '.draft')
    local pr_state=$(echo "$pr_details" | jq -r '.state')
    local pr_url=$(echo "$pr_details" | jq -r '.html_url')
    
    printf "${BLUE}PR Title: ${pr_title}${NC}\n"
    printf "${BLUE}PR State: ${pr_state}${NC}\n"
    printf "${BLUE}Is Draft: ${is_draft}${NC}\n"
    printf "${BLUE}PR URL: ${pr_url}${NC}\n"
    
    # Check if PR is open
    if [ "$pr_state" != "open" ]; then
        printf "${YELLOW}PR #${pr_number} is not open (state: $pr_state) - cannot mark as ready${NC}\n"
        exit 0
    fi
    
    # Check if PR is already ready for review
    if [ "$is_draft" = "false" ]; then
        if [ "$force" = "true" ]; then
            printf "${YELLOW}PR #${pr_number} is already ready for review, but forcing update...${NC}\n"
            mark_pr_ready "$pr_number"
        else
            printf "${GREEN}PR #${pr_number} is already ready for review - no action needed${NC}\n"
        fi
    else
        printf "${YELLOW}PR #${pr_number} is currently a draft - marking as ready for review...${NC}\n"
        mark_pr_ready "$pr_number"
    fi
}

# Run main function with all arguments
main "$@"
