#!/bin/bash

# check-review-status.sh - Check Google Code Assist review status for a branch or PR
# Usage: ./check-review-status.sh [branch-name|pr-number] [--wait] [--poll-interval SECONDS]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_OWNER="sheepdestroyer"
REPO_NAME="SheepVibes"
TRACKING_FILE="pr-review-tracker.json"
GITHUB_API_BASE="https://api.github.com"

# Function to print usage
usage() {
    echo "Usage: $0 [branch-name|pr-number] [--wait] [--poll-interval SECONDS]"
    echo ""
    echo "Examples:"
    echo "  $0 feat/new-widget"
    echo "  $0 123"
    echo "  $0 feat/new-widget --wait"
    echo "  $0 123 --wait --poll-interval 30"
    echo ""
    echo "This script checks the Google Code Assist review status for a given branch or PR number."
    echo "Returns: None, Started, or Commented"
    echo ""
    echo "Options:"
    echo "  --wait              Wait for comments to be available"
    echo "  --poll-interval SEC  Polling interval in seconds (default: 60)"
    echo ""
    echo "When --wait is used and comments are found, they are saved to comments.json"
}

# Function to check if required tools are available
check_dependencies() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Error: jq is required but not installed.${NC}"
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is required but not installed.${NC}"
        exit 1
    fi
}

# Function to make GitHub API request with rate limit handling
github_api_request() {
    local endpoint="$1"
    local url="${GITHUB_API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}${endpoint}"
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        local response
        local http_code
        
        if [ -z "$GITHUB_TOKEN" ]; then
            echo -e "${YELLOW}Warning: GITHUB_TOKEN not set. Using unauthenticated requests (rate limited).${NC}" >&2
            response=$(curl -s -w "\n%{http_code}" -H "Accept: application/vnd.github.v3+json" "$url")
        else
            response=$(curl -s -w "\n%{http_code}" -H "Authorization: token $GITHUB_TOKEN" \
                 -H "Accept: application/vnd.github.v3+json" \
                 "$url")
        fi
        
        http_code=$(echo "$response" | tail -n1)
        local response_body=$(echo "$response" | head -n -1)
        
        # Check for rate limiting (HTTP 429 or 403 with rate limit message)
        if [ "$http_code" = "429" ] || [ "$http_code" = "403" ]; then
            local reset_time
            if [ -n "$GITHUB_TOKEN" ]; then
                reset_time=$(curl -s -I -H "Authorization: token $GITHUB_TOKEN" \
                    "$url" | grep -i "x-ratelimit-reset" | cut -d' ' -f2 | tr -d '\r')
            else
                reset_time=$(curl -s -I "$url" | grep -i "x-ratelimit-reset" | cut -d' ' -f2 | tr -d '\r')
            fi
            
            if [ -n "$reset_time" ]; then
                local current_time=$(date +%s)
                local wait_time=$((reset_time - current_time + 10))  # Add 10 seconds buffer
                
                if [ $wait_time -gt 0 ]; then
                    echo -e "${YELLOW}Rate limit hit. Waiting ${wait_time} seconds...${NC}" >&2
                    sleep $wait_time
                    retry_count=$((retry_count + 1))
                    continue
                fi
            fi
        fi
        
        # Check for successful response
        if [ "$http_code" = "200" ]; then
            echo "$response_body"
            return 0
        fi
        
        # For other errors, retry with exponential backoff
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            local backoff_time=$((2 ** retry_count))
            echo -e "${YELLOW}API request failed (HTTP $http_code). Retrying in ${backoff_time}s...${NC}" >&2
            sleep $backoff_time
        fi
    done
    
    echo -e "${RED}Failed to make GitHub API request after ${max_retries} attempts${NC}" >&2
    return 1
}

# Function to get PR number from branch name
get_pr_from_branch() {
    local branch_name="$1"
    
    # Get open PRs for this branch
    local pr_data=$(github_api_request "/pulls?head=${REPO_OWNER}:${branch_name}&state=open")
    
    if [ "$(echo "$pr_data" | jq length)" -gt 0 ]; then
        echo "$pr_data" | jq -r '.[0].number'
    else
        echo ""
    fi
}

# Function to extract and save Google Code Assist comments
extract_google_comments() {
    local pr_number="$1"
    local comments_file="$2"
    
    # Get all comments for this PR
    local comments=$(github_api_request "/issues/${pr_number}/comments")
    local review_comments=$(github_api_request "/pulls/${pr_number}/comments")
    
    # Combine and filter for Google Code Assist comments
    local all_comments=$(echo "$comments" "$review_comments" | jq -s 'add')
    
    # Filter for Google Code Assist comments and extract relevant info
    echo "$all_comments" | jq '
    [
        .[] | 
        select(
            (.user.login | test("[Gg]oogle|[Cc]ode|[Aa]ssist|[Bb]ot")) or
            (.body | test("[Gg]oogle|[Cc]ode|[Aa]ssist"))
        ) |
        {
            id: .id,
            user: .user.login,
            body: .body,
            created_at: .created_at,
            html_url: .html_url,
            path: (.path // ""),
            position: (.position // ""),
            line: (.line // "")
        }
    ]' > "$comments_file"
    
    local comment_count=$(jq length "$comments_file")
    echo "$comment_count"
}

# Function to check review status for a PR
check_pr_review_status() {
    local pr_number="$1"
    local wait_for_comments="$2"
    local poll_interval="$3"
    
    echo -e "${BLUE}Checking review status for PR #${pr_number}...${NC}"
    
    # Get PR details
    local pr_details=$(github_api_request "/pulls/${pr_number}")
    local pr_title=$(echo "$pr_details" | jq -r '.title')
    local pr_state=$(echo "$pr_details" | jq -r '.state')
    
    if [ "$pr_state" != "open" ]; then
        echo -e "${YELLOW}PR #${pr_number} is not open (state: $pr_state)${NC}"
        echo "None"
        return
    fi
    
    echo -e "${BLUE}PR Title: ${pr_title}${NC}"
    
    # Get reviews for this PR
    local reviews=$(github_api_request "/pulls/${pr_number}/reviews")
    local review_count=$(echo "$reviews" | jq length)
    
    # Get comments for this PR
    local comments=$(github_api_request "/issues/${pr_number}/comments")
    local comment_count=$(echo "$comments" | jq length)
    
    echo -e "${BLUE}Found ${review_count} reviews and ${comment_count} comments${NC}"
    
    # Check for Google Code Assist activity
    # Google Code Assist typically appears as a user or bot account
    local google_assist_found=false
    local google_comments=0
    
    # Check reviews for Google Code Assist
    for i in $(seq 0 $((review_count - 1))); do
        local reviewer=$(echo "$reviews" | jq -r ".[$i].user.login")
        local state=$(echo "$reviews" | jq -r ".[$i].state")
        
        # Check for Google Code Assist patterns
        if [[ "$reviewer" =~ [Gg]oogle|[Cc]ode|[Aa]ssist|[Bb]ot ]]; then
            google_assist_found=true
            echo -e "${GREEN}Found Google Code Assist review: ${state}${NC}"
        fi
    done
    
    # Check comments for Google Code Assist
    for i in $(seq 0 $((comment_count - 1))); do
        local commenter=$(echo "$comments" | jq -r ".[$i].user.login")
        local body=$(echo "$comments" | jq -r ".[$i].body")
        
        # Check for Google Code Assist patterns
        if [[ "$commenter" =~ [Gg]oogle|[Cc]ode|[Aa]ssist|[Bb]ot ]] || \
           [[ "$body" =~ [Gg]oogle|[Cc]ode|[Aa]ssist ]]; then
            google_comments=$((google_comments + 1))
        fi
    done
    
    # If waiting for comments and none found, poll until comments are available
    if [ "$wait_for_comments" = "true" ] && [ $google_comments -eq 0 ]; then
        echo -e "${YELLOW}Waiting for Google Code Assist comments (polling every ${poll_interval}s)...${NC}"
        local poll_count=0
        local max_polls=60  # Maximum 1 hour of polling (60 * 60s)
        
        while [ $google_comments -eq 0 ] && [ $poll_count -lt $max_polls ]; do
            sleep "$poll_interval"
            poll_count=$((poll_count + 1))
            
            # Re-check for comments
            comments=$(github_api_request "/issues/${pr_number}/comments")
            comment_count=$(echo "$comments" | jq length)
            google_comments=0
            
            for i in $(seq 0 $((comment_count - 1))); do
                local commenter=$(echo "$comments" | jq -r ".[$i].user.login")
                local body=$(echo "$comments" | jq -r ".[$i].body")
                
                if [[ "$commenter" =~ [Gg]oogle|[Cc]ode|[Aa]ssist|[Bb]ot ]] || \
                   [[ "$body" =~ [Gg]oogle|[Cc]ode|[Aa]ssist ]]; then
                    google_comments=$((google_comments + 1))
                fi
            done
            
            echo -e "${BLUE}Poll ${poll_count}/${max_polls}: ${google_comments} Google Code Assist comments found${NC}"
        done
        
        if [ $google_comments -eq 0 ]; then
            echo -e "${YELLOW}No Google Code Assist comments received after ${max_polls} polls${NC}"
        fi
    fi
    
    # Extract and save comments if any are found
    if [ $google_comments -gt 0 ]; then
        local comments_file="comments_${pr_number}.json"
        local extracted_count=$(extract_google_comments "$pr_number" "$comments_file")
        echo -e "${GREEN}Google Code Assist has provided ${extracted_count} comment(s) - saved to ${comments_file}${NC}"
        echo "Commented"
    elif [ "$google_assist_found" = true ]; then
        echo -e "${YELLOW}Google Code Assist has started review but no comments yet${NC}"
        echo "Started"
    else
        echo -e "${YELLOW}No Google Code Assist activity detected${NC}"
        echo "None"
    fi
}

# Function to update tracking file with simple locking
update_tracking_file() {
    local branch_name="$1"
    local pr_number="$2"
    local review_status="$3"
    
    # Simple file locking using a lock file
    local lock_file="${TRACKING_FILE}.lock"
    local lock_timeout=30
    local lock_attempt=0
    
    # Wait for lock with timeout
    while [ -f "$lock_file" ] && [ $lock_attempt -lt $lock_timeout ]; do
        sleep 1
        lock_attempt=$((lock_attempt + 1))
    done
    
    if [ -f "$lock_file" ]; then
        echo -e "${YELLOW}Warning: Could not acquire lock for tracking file after ${lock_timeout} seconds${NC}"
        return 1
    fi
    
    # Create lock file
    touch "$lock_file"
    
    if [ ! -f "$TRACKING_FILE" ]; then
        # Create initial tracking file
        cat > "$TRACKING_FILE" << EOF
{
  "branches": {},
  "last_updated": "$(date -Iseconds)"
}
EOF
    fi
    
    # Update tracking file
    local temp_file=$(mktemp)
    if jq --arg branch "$branch_name" \
          --arg pr "$pr_number" \
          --arg status "$review_status" \
          --arg updated "$(date -Iseconds)" \
          '.branches[$branch] = {
            pr_number: ($pr | tonumber? // $pr),
            review_status: $status,
            last_updated: $updated
          } | .last_updated = $updated' \
          "$TRACKING_FILE" > "$temp_file"; then
        mv "$temp_file" "$TRACKING_FILE"
        echo -e "${GREEN}Updated tracking file: $TRACKING_FILE${NC}"
    else
        echo -e "${RED}Error: Failed to update tracking file${NC}"
        rm -f "$temp_file"
    fi
    
    # Remove lock file
    rm -f "$lock_file"
}

# Main function
main() {
    local input=""
    local wait_for_comments="false"
    local poll_interval=60
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            --wait)
                wait_for_comments="true"
                shift
                ;;
            --poll-interval)
                poll_interval="$2"
                shift 2
                ;;
            *)
                input="$1"
                shift
                ;;
        esac
    done
    
    if [ -z "$input" ]; then
        usage
        exit 1
    fi
    
    check_dependencies
    
    local pr_number=""
    local branch_name=""
    
    # Determine if input is PR number or branch name
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        pr_number="$input"
        echo -e "${BLUE}Checking PR #${pr_number}${NC}"
    else
        branch_name="$input"
        echo -e "${BLUE}Checking branch: ${branch_name}${NC}"
        pr_number=$(get_pr_from_branch "$branch_name")
        
        if [ -z "$pr_number" ]; then
            echo -e "${RED}No open PR found for branch: ${branch_name}${NC}"
            echo "None"
            exit 1
        fi
    fi
    
    # Check review status
    local review_status=$(check_pr_review_status "$pr_number" "$wait_for_comments" "$poll_interval")
    
    # Update tracking file if branch name was provided
    if [ -n "$branch_name" ]; then
        update_tracking_file "$branch_name" "$pr_number" "$review_status"
    fi
    
    echo "$review_status"
}

# Run main function with all arguments
main "$@"
