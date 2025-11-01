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
REPO_SLUG=$(git remote get-url origin 2>/dev/null | sed -e 's/.*github.com[:\/]//' -e 's/\.git$//')
if [ -n "$REPO_SLUG" ]; then
    REPO_OWNER=$(echo "$REPO_SLUG" | cut -d'/' -f1)
    REPO_NAME=$(echo "$REPO_SLUG" | cut -d'/' -f2)
else
    # Fallback to hardcoded values if git remote is not available
    REPO_OWNER="sheepdestroyer"
    REPO_NAME="SheepVibes"
fi
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
    echo "When --wait is used and comments are found, they are saved to comments_<PR#>.json"
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
        local headers_file=$(mktemp)
        
        if [ -z "$GITHUB_TOKEN" ]; then
            echo -e "${YELLOW}Warning: GITHUB_TOKEN not set. Using unauthenticated requests (rate limited).${NC}" >&2
            response=$(curl -s -w "\n%{http_code}" -D "$headers_file" -H "Accept: application/vnd.github.v3+json" "$url")
        else
            response=$(curl -s -w "\n%{http_code}" -D "$headers_file" -H "Authorization: token $GITHUB_TOKEN" \
                 -H "Accept: application/vnd.github.v3+json" \
                 "$url")
        fi
        
        http_code=$(echo "$response" | tail -n1)
        local response_body=$(echo "$response" | head -n -1)
        
        # Check for rate limiting (HTTP 429 or 403 with rate limit message)
        if [ "$http_code" = "429" ] || { [ "$http_code" = "403" ] && echo "$response_body" | grep -q "API rate limit exceeded"; }; then
            local reset_time
            reset_time=$(grep -i "x-ratelimit-reset" "$headers_file" | cut -d' ' -f2 | tr -d '\r')
            rm -f "$headers_file"
            
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
        else
            # Clean up headers file if not rate limited
            rm -f "$headers_file"
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

# Function to extract and save Google Code Assist comments from timeline
extract_google_comments() {
    local pr_number="$1"
    local comments_file="$2"
    
    # Get all reviews for this PR
    local reviews=$(github_api_request "/pulls/${pr_number}/reviews")
    
    # Filter for comments made by Google Code Assist and extract relevant info
    echo "$reviews" | jq '
    [
        .[] | 
        select(
            .user.login == "gemini-code-assist[bot]" and .body
        )
    ] | sort_by(.submitted_at) | reverse | .[0] | {
        id: .id,
        user: .user.login,
        body: .body,
        submitted_at: .submitted_at,
        html_url: .html_url
    }' > "$comments_file"
    
    local comment_count=$(jq 'if . == null then 0 else 1 end' "$comments_file")
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
local reviews
    local review_count
    for i in {1..3}; do
        reviews=$(github_api_request "/pulls/${pr_number}/reviews")
        review_count=$(echo "$reviews" | jq length)
        if [ "$review_count" -gt 5 ]; then
            break
        fi
        sleep 10
    done
    echo -e "${BLUE}Found ${review_count} reviews${NC}"
    
    # Check for Google Code Assist activity
    local google_assist_found=false
    local google_comments=0
    
    # Check reviews for Google Code Assist
    local assist_reviews
    assist_reviews=$(echo "$reviews" | jq -r '[.[] | select(.user.login == "gemini-code-assist[bot]")] | .[0] | .state')
    if [ -n "$assist_reviews" ]; then
        google_assist_found=true
        echo "$assist_reviews" | while read -r state; do
            echo -e "${GREEN}Found Google Code Assist review: ${state}${NC}"
        done
    fi
    
    # Check comments for Google Code Assist using single jq command
    google_comments=$(echo "$reviews" | jq '[.[] | select(.user.login | test("gemini-code-assist|Google Code Assist"))] | length')
    if [ "$google_comments" -gt 0 ]; then
        echo "$reviews" | jq -c '.[] | select(.user.login | test("gemini-code-assist|Google Code Assist"))' | while read -r comment; do
            body=$(echo "$comment" | jq -r '.body')
                echo "Processing comment: $body"
                if echo "$body" | grep -q "No remaining issues"; then
                echo "Gemini Code Assist has no remaining issues."
                exit 2
            fi
        done
    fi
    
    # If waiting for comments and none found, poll until comments are available
    if [ "$wait_for_comments" = "true" ] && [ $google_comments -eq 0 ]; then
        echo -e "${YELLOW}Waiting for Google Code Assist comments (polling every ${poll_interval}s)...${NC}"
        local poll_count=0
        local max_polls=60  # Maximum 1 hour of polling (60 * 60s)
        
        while [ $google_comments -eq 0 ] && [ $poll_count -lt $max_polls ]; do
            sleep "$poll_interval"
            poll_count=$((poll_count + 1))
            
            # Re-check for comments
            reviews=$(github_api_request "/pulls/${pr_number}/reviews")
            review_count=$(echo "$reviews" | jq length)
            google_comments=$(echo "$reviews" | jq '[.[] | select(.user.login | test("gemini-code-assist") or (.body | test("Google Code Assist")))] | length')
            
            echo -e "${BLUE}Poll ${poll_count}/${max_polls}: ${google_comments} Google Code Assist comments found${NC}"
        done
        
        if [ $google_comments -eq 0 ]; then
            echo -e "${YELLOW}No Google Code Assist commentsMATRIX Labs, a creator of open-source artificial intelligence (AI) and machine learning (ML) tools, has announced the launch of its new open-source platform, MATRIX VISION. The platform is designed to help developers build computer vision applications for the Internet of Things (IoT) and other devices.

MATRIX VISION is a free and open-source platform that provides developers with a complete set of tools for building and deploying computer vision applications. The platform includes a graphical user interface (GUI) for creating and training models, a set of pre-trained models for common computer vision tasks, and a software development kit (SDK) for deploying models to devices.

received after ${max_polls} polls${NC}"
        fi
    fi
    
    # Extract and save comments if any are found
    if [ $google_comments -gt 0 ]; then
        local comments_file="comments_${pr_number}.json"
        local extracted_count=$(extract_google_comments "$pr_number" "$comments_file")
        if [ $extracted_count -gt 0 ]; then
            echo -e "${GREEN}Google Code Assist has provided ${extracted_count} comment(s) - saved to ${comments_file}${NC}"
            echo "Commented"
        else
             echo -e "${YELLOW}No new Google Code Assist comments found${NC}"
             echo "Started"
        fi
    elif [ "$google_assist_found" = true ]; then
        echo -e "${YELLOW}Google Code Assist has started review but no comments yet${NC}"
        echo "Started"
    else
        echo -e "${YELLOW}No Google Code Assist activity detected${NC}"
        echo "None"
    fi
}

# Function to update tracking file with atomic flock locking and comment tracking
update_tracking_file() {
    local branch_name="$1"
    local pr_number="$2"
    local review_status="$3"
    local comments_file="$4"
    local lock_file="${TRACKING_FILE}.lock"
    local lock_timeout=30

    (
        # Atomically acquire an exclusive lock with a timeout.
        if ! flock -x -w "$lock_timeout" 200; then
            echo -e "${YELLOW}Warning: Could not acquire lock for tracking file after ${lock_timeout} seconds${NC}" >&2
            exit 1
        fi

        if [ ! -f "$TRACKING_FILE" ]; then
            # Create initial tracking file
            cat > "$TRACKING_FILE" << EOF
{
  "branches": {},
  "last_updated": "$(date -Iseconds)"
}
EOF
        fi

        # Get existing branch data to preserve comments
        local existing_comments="[]"
        if jq -e ".branches[\"$branch_name\"].comments" "$TRACKING_FILE" > /dev/null 2>&1; then
            existing_comments=$(jq -c ".branches[\"$branch_name\"].comments // []" "$TRACKING_FILE")
        fi

        # If new comments are available, prepare them for insertion
        local new_comments="[]"
        if [ -n "$comments_file" ] && [ -f "$comments_file" ]; then
            # Map new comments to the required structure with "todo" status
            new_comments=$(jq '[.[] | {id: .id, status: "todo", body: .body, created_at: .created_at}]' "$comments_file")
        fi

        # Combine existing and new comments, avoiding duplicates by id
        local all_comments=$(jq -s '(.[0] + .[1]) | unique_by(.id)' <(echo "$existing_comments") <(echo "$new_comments"))

        # Update tracking file
        local temp_file=$(mktemp)
        if jq --arg branch "$branch_name" \
              --arg pr "$pr_number" \
              --arg status "$review_status" \
              --arg updated "$(date -Iseconds)" \
              --argjson comments "$all_comments" \
              '.branches[$branch] = {
                pr_number: ($pr | tonumber? // $pr),
                review_status: $status,
                last_updated: $updated,
                comments: $comments
              } | .last_updated = $updated' \
              "$TRACKING_FILE" > "$temp_file"; then
            mv "$temp_file" "$TRACKING_FILE"
            echo -e "${GREEN}Updated tracking file: $TRACKING_FILE${NC}"
        else
            echo -e "${RED}Error: Failed to update tracking file${NC}" >&2
            rm -f "$temp_file"
            exit 1
        fi
    ) 200>"$lock_file"
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
            echo -e "${RED}No open PR found for branch: ${branch_name}${NC}" >&2
            echo "None"
            exit 0
        fi
    fi
    
    # Check review status
    local review_status=$(check_pr_review_status "$pr_number" "$wait_for_comments" "$poll_interval")
    
    # Update tracking file if branch name was provided
    if [ -n "$branch_name" ]; then
        local comments_file=""
        if [ "$review_status" = "Commented" ]; then
            comments_file="comments_${pr_number}.json"
        fi
        update_tracking_file "$branch_name" "$pr_number" "$review_status" "$comments_file"
    fi
    
    echo "$review_status"
}

# Run main function with all arguments
main "$@"
