#!/bin/bash

# ensure-pr-ready-workflow.sh - Workflow to ensure all opened PRs are marked as "Ready for review"
# This script integrates with the existing PR review tracking system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TRACKING_FILE="pr-review-tracker.json"
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
Usage: $0 [options]

Ensures that all open pull requests are marked as "Ready for review".

This workflow:
1. Checks all open PRs in the repository
2. Identifies any draft PRs
3. Marks draft PRs as ready for review
4. Updates the PR review tracking system

Options:
  --dry-run    Show what would be done without making changes
  --branch BRANCH  Only check PRs from the specified branch
  --help       Show this help message

Examples:
  $0                    # Ensure all open PRs are ready for review
  $0 --dry-run          # Show which PRs would be marked as ready
  $0 --branch feat/new  # Only check PRs from the 'feat/new' branch

Exit Codes:
  0 - Success
  1 - Error occurred
EOF
}



# Function to get all open PRs
get_open_prs() {
    local branch_filter="$1"
    local endpoint="/pulls?state=open&per_page=100"
    
    if [ -n "$branch_filter" ]; then
        endpoint="${endpoint}&head=${REPO_OWNER}:${branch_filter}"
    fi
    
    github_api_request "$endpoint"
}


# Main function
main() {
    local dry_run=false
    local branch_filter=""
    
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --branch)
                if [ $# -lt 2 ]; then
                    printf "${RED}Error: --branch requires a branch name${NC}\n" >&2
                    exit 1
                fi
                branch_filter="$2"
                shift 2
                ;;
            *)
                printf "${RED}Error: Unknown option '$1'${NC}\n" >&2
                usage
                exit 1
                ;;
        esac
    done
    
    printf "${BLUE}Starting PR readiness workflow...${NC}\n"
    printf "${BLUE}Repository: ${REPO_OWNER}/${REPO_NAME}${NC}\n"
    if [ -n "$branch_filter" ]; then
        printf "${BLUE}Branch filter: ${branch_filter}${NC}\n"
    fi
    if [ "$dry_run" = "true" ]; then
        printf "${YELLOW}DRY RUN MODE - No changes will be made${NC}\n"
    fi
    printf "\n"
    
    # Get all open PRs
    printf "${BLUE}Fetching open pull requests...${NC}\n"
    prs_data=$(get_open_prs "$branch_filter")
    
    local pr_count=$(echo "$prs_data" | jq length)
    printf "${BLUE}Found ${pr_count} open pull request(s)${NC}\n\n"
    
    if [ "$pr_count" -eq 0 ]; then
        printf "${GREEN}No open PRs found - nothing to do${NC}\n"
        exit 0
    fi
    
    local processed_count=0
    local marked_ready_count=0
    local errors_count=0
    
    # Process each PR
    for ((i=0; i<pr_count; i++)); do
        local pr=$(echo "$prs_data" | jq ".[$i]")
        local pr_number=$(echo "$pr" | jq -r '.number')
        local pr_title=$(echo "$pr" | jq -r '.title')
        local is_draft=$(echo "$pr" | jq -r '.draft')
        local head_branch=$(echo "$pr" | jq -r '.head.ref')
        local pr_url=$(echo "$pr" | jq -r '.html_url')
        
        printf "${BLUE}Processing PR #${pr_number}: ${pr_title}${NC}\n"
        printf "  Branch: ${head_branch}\n"
        printf "  URL: ${pr_url}\n"
        printf "  Draft: ${is_draft}\n"
        
        processed_count=$((processed_count + 1))
        
        local should_update_tracker=false
        if [ "$is_draft" = "true" ]; then
            printf "  ${YELLOW}Status: DRAFT - needs to be marked as ready${NC}\n"
            
            if mark_pr_ready "$pr_number" "$dry_run"; then
                marked_ready_count=$((marked_ready_count + 1))
                should_update_tracker=true
            else
                errors_count=$((errors_count + 1))
            fi
        else
            printf "  ${GREEN}Status: Already ready for review${NC}\n"
            should_update_tracker=true
        fi

        if [ "$dry_run" = "false" ] && [ "$should_update_tracker" = "true" ]; then
            ./check-review-status.sh "$head_branch"
            printf "  ${GREEN}Tracking updated for branch ${head_branch}${NC}\n"
        fi
        
        printf "\n"
    done
    
    # Summary
    printf "${BLUE}=== Workflow Summary ===${NC}\n"
    printf "Processed: ${processed_count} PR(s)\n"
    printf "Marked as ready: ${marked_ready_count} PR(s)\n"
    printf "Errors: ${errors_count}\n"
    
    if [ "$dry_run" = "true" ]; then
        printf "${YELLOW}DRY RUN COMPLETED - No actual changes were made${NC}\n"
    else
        printf "${GREEN}Workflow completed successfully${NC}\n"
    fi
}

# Run main function with all arguments
main "$@"

