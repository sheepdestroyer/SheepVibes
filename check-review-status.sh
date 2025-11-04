#!/bin/bash

# check-review-status.sh - Check Google Code Assist review status for a branch or PR
# Usage: ./check-review-status.sh [branch-name|pr-number] [--wait] [--poll-interval SECONDS]

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/common.sh"

# Configuration
TRACKING_FILE="pr-review-tracker.json"
MAX_POLLS=5
DEFAULT_POLL_INTERVAL=120
GOOGLE_BOT_USERNAME="${GOOGLE_BOT_USERNAME:-gemini-code-assist[bot]}"

# Global array to track temporary files for cleanup
TEMP_FILES=()

# Cleanup function to remove temporary files
cleanup() {
    rm -f "${TEMP_FILES[@]}"
}

# Register cleanup function to run on exit
trap cleanup EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get repository owner and name
get_repo_info

# Function to print usage
usage() {
    cat << EOF
Usage: $0 [branch-name|pr-number] [--wait] [--poll-interval SECONDS] [--max-polls NUM]

Examples:
  $0 feat/new-widget
  $0 123
  $0 feat/new-widget --wait
  $0 123 --wait --poll-interval 30

This script checks the Google Code Assist review status for a given branch or PR number.
Returns: None, Commented, Complete, or RateLimited

Exit Codes:
  0 - Success with review status output
  1 - Error occurred (e.g., authentication, API failure)
  2 - No open PR found for the given branch, or the PR is not open

Options:
  --wait                Wait for comments to be available (uses poll-interval for all waits)
  --poll-interval SEC   Polling interval in seconds (default: 120)
  --max-polls NUM       Maximum number of polling attempts (default: 5)

When --wait is used and comments are found, they are saved to comments_<PR#>.json
EOF
}

# Function to get PR info from branch name
get_pr_info_from_branch() {
    local branch_name="$1"
    
    # Get open PRs for this branch
    local pr_data
    if ! pr_data=$(github_api_request "/pulls?head=${REPO_OWNER}:$(echo -n "$branch_name" | jq -sRr @uri)&state=open"); then
        return 1  # Propagate API request failure
    fi
    
    if [ "$(echo "$pr_data" | jq length)" -gt 0 ]; then
        echo "$pr_data" | jq -r '.[0] | {number: .number, title: .title, state: .state}'
    else
        echo ""
    fi
}

# Function to check if Google Code Assist has indicated no remaining issues
check_for_no_remaining_issues() {
    local comments_file="$1"
    
    # Check if any comment contains a completion signal
    # Use more specific patterns to avoid matching comments about the feature itself
    if jq -e 'any(.[] | .body; test("^(No remaining issues|All issues resolved|All fixed|No issues remaining)"; "i"))' "$comments_file" > /dev/null; then
        return 0  # Completion signal found
    fi
    
    return 1  # No completion signal found
}

# Function to check if Google Code Assist has hit daily quota limit
check_for_rate_limit() {
    local comments_file="$1"

    # Find the most recent rate limit message
    local rate_limit_comment=$(jq -r '
        [.[] | select(.body | test("(> )?You have reached your daily quota limit"; "i"))] 
        | sort_by(.submitted_at) 
        | last
    ' "$comments_file")

    # If no rate limit message found, return false
    if [ "$rate_limit_comment" = "null" ] || [ -z "$rate_limit_comment" ]; then
        return 1  # No rate limit detected
    fi

    # Extract the timestamp of the rate limit message
    local rate_limit_time=$(echo "$rate_limit_comment" | jq -r '.submitted_at')
    
    # Check if there are any comments that came AFTER the rate limit message
    local newer_comments=$(jq --arg rate_limit_time "$rate_limit_time" '
        [.[] | select(.submitted_at > $rate_limit_time)] | length
    ' "$comments_file")

    # If there are newer comments, the quota may have reset - don't pause
    if [ "$newer_comments" -gt 0 ]; then
        echo -e "${YELLOW}Rate limit detected but newer comments exist - continuing workflow${NC}" >&2
        return 1  # Don't pause workflow
    fi

    # Check if 24 hours have passed since the rate limit message
    local current_time=$(date -u +%s)
    local rate_limit_timestamp=$(date -u -d "$rate_limit_time" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$rate_limit_time" +%s 2>/dev/null)
    
    if [ -n "$rate_limit_timestamp" ]; then
        local time_since_rate_limit=$((current_time - rate_limit_timestamp))
        local twenty_four_hours=$((24 * 60 * 60))
        
        if [ "$time_since_rate_limit" -ge "$twenty_four_hours" ]; then
            echo -e "${YELLOW}Rate limit detected but 24 hours have passed - continuing workflow${NC}" >&2
            return 1  # Don't pause workflow
        fi
    fi

    # If we get here, rate limit is active and workflow should pause
    echo -e "${YELLOW}Active rate limit detected - workflow paused${NC}" >&2
    return 0  # Rate limit active, pause workflow
}

# Function to extract and save Google Code Assist comments from timeline with pagination
extract_google_comments() {
    local pr_number="$1"
    local comments_file="$2"
    
    # Create a temporary file to collect raw JSON objects (one per line)
    local raw_temp_file=$(mktemp "${TMPDIR:-/tmp}/review-status-raw.XXXXXX")
    TEMP_FILES+=("$raw_temp_file")
    local page=1
    local has_more=true
    
    while [ "$has_more" = true ]; do
        # Use the /pulls/{pr_number}/comments endpoint to get line comments
        local comments_page=$(github_api_request "/pulls/${pr_number}/comments?page=${page}&per_page=100")
        local comment_count=$(echo "$comments_page" | jq length)
        
        if [ "$comment_count" -gt 0 ]; then
            # Write each comment as a separate JSON object on its own line
            echo "$comments_page" | jq -c '.[]' >> "$raw_temp_file"
            page=$((page + 1))
        else
            has_more=false
        fi
    done

    # Also get issue comments (where Google Code Assist posts summary comments)
    page=1
    has_more=true
    while [ "$has_more" = true ]; do
        local issue_comments_page=$(github_api_request "/issues/${pr_number}/comments?page=${page}&per_page=100")
        local issue_comment_count=$(echo "$issue_comments_page" | jq length)
        
        if [ "$issue_comment_count" -gt 0 ]; then
            # Write each comment as a separate JSON object on its own line
            echo "$issue_comments_page" | jq -c '.[]' >> "$raw_temp_file"
            page=$((page + 1))
        else
            has_more=false
        fi
    done
    
    # Filter for comments made by Google Code Assist and extract relevant info
    # Note: we alias 'created_at' to 'submitted_at' for consistency with the tracking file format.
    jq --arg bot_username "$GOOGLE_BOT_USERNAME" -s '
    [
        .[] |
        select(
            .user.login == $bot_username
        ) | {
            id: .id,
            user: .user.login,
            body: .body,
            submitted_at: .created_at,
            html_url: .html_url
        }
    ]' "$raw_temp_file" > "$comments_file"
    
    # Temporary file will be cleaned up by trap handler via TEMP_FILES array
    
    local total_comment_count=$(jq length "$comments_file")
    echo "$total_comment_count"
}

# Function to check review status for a PR
check_pr_review_status() {
    local pr_number="$1"
    local wait_for_comments="$2"
    local poll_interval="$3"
    local max_polls="$4"
    local pr_title="$5"
    local pr_state="$6"
    
    echo -e "${BLUE}Checking review status for PR #${pr_number}...${NC}" >&2
    
    if [ -z "$pr_title" ] || [ -z "$pr_state" ]; then
        local pr_details=$(github_api_request "/pulls/${pr_number}")
        pr_title=$(echo "$pr_details" | jq -r '.title')
        pr_state=$(echo "$pr_details" | jq -r '.state')
    fi
    
    if [ "$pr_state" != "open" ]; then
        echo -e "${YELLOW}PR #${pr_number} is not open (state: $pr_state)${NC}" >&2
        echo "{\"status\": \"None\", \"comments\": 0}"
        return 2
    fi
    
    echo -e "${BLUE}PR Title: ${pr_title}${NC}" >&2
    
    # Check for Google Code Assist activity
    local comments_file="comments_${pr_number}.json"
    
    # Extract initial Google Code Assist comments
    local google_comments
    google_comments=$(extract_google_comments "$pr_number" "$comments_file")
    
    # If waiting for comments, poll until NEW comments are available
    if [ "$wait_for_comments" = "true" ]; then
        echo -e "${YELLOW}Waiting for NEW Google Code Assist comments (initial ${poll_interval}s wait, then polling every ${poll_interval}s)...${NC}" >&2
        
        local initial_comment_count=$google_comments
        local poll_count=0

        echo -e "${BLUE}Initial comment count: ${initial_comment_count}${NC}" >&2

        # Initial wait
        echo -e "${BLUE}Initial wait: ${poll_interval} seconds...${NC}" >&2
        sleep "$poll_interval"
        poll_count=$((poll_count + 1))

        # Re-check for comments after initial wait
        google_comments=$(extract_google_comments "$pr_number" "$comments_file")
        echo -e "${BLUE}After initial wait: ${google_comments} Google Code Assist comments found${NC}" >&2

        # Continue polling every poll_interval seconds if no NEW comments found
        while [ "$google_comments" -eq "$initial_comment_count" ] && [ "$poll_count" -lt "$max_polls" ]; do
            echo -e "${BLUE}Sleeping for ${poll_interval} seconds...${NC}" >&2
            sleep "$poll_interval"
            poll_count=$((poll_count + 1))

            # Re-check for comments
            google_comments=$(extract_google_comments "$pr_number" "$comments_file")

            echo -e "${BLUE}Poll ${poll_count}/${max_polls}: ${google_comments} Google Code Assist comments found (waiting for increase from ${initial_comment_count})${NC}" >&2
        done

        if [ "$google_comments" -eq "$initial_comment_count" ]; then
            echo -e "${YELLOW}No NEW Google Code Assist comments received after ${max_polls} polls${NC}" >&2
        else
            echo -e "${GREEN}NEW comments detected! Increased from ${initial_comment_count} to ${google_comments}${NC}" >&2
        fi
    fi

    if [ "$google_comments" -gt 0 ]; then
        echo -e "${GREEN}Google Code Assist has provided ${google_comments} comment(s) - saved to ${comments_file}${NC}" >&2
        
        # Check if Google Code Assist has hit daily quota limit
        if check_for_rate_limit "$comments_file"; then
            echo -e "${YELLOW}Google Code Assist has reached daily quota limit - review cycle paused${NC}" >&2
            echo "{\"status\": \"RateLimited\", \"comments\": ${google_comments}}"
        # Check if Google Code Assist has indicated no remaining issues
        elif check_for_no_remaining_issues "$comments_file"; then
            echo -e "${GREEN}Google Code Assist indicates no remaining issues - review cycle complete${NC}" >&2
            echo "{\"status\": \"Complete\", \"comments\": ${google_comments}}"
        else
            echo "{\"status\": \"Commented\", \"comments\": ${google_comments}}"
        fi
    else
        echo -e "${YELLOW}No Google Code Assist activity detected${NC}" >&2
        echo "{\"status\": \"None\", \"comments\": 0}"
    fi
}

# Function to update tracking file with atomic flock locking and comment tracking
update_tracking_file() {
    local branch_name="$1"
    local pr_number="$2"
    local review_status="$3"
    local comments_file="$4"
    local pr_state="$5"
    local lock_file="${TRACKING_FILE}.lock"
    local lock_timeout=30

    # Use file descriptor 200 for flock locking
    exec 200>"$lock_file"
    
    # Atomically acquire an exclusive lock with a timeout.
    if ! flock -x -w "$lock_timeout" 200; then
        echo -e "${YELLOW}Warning: Could not acquire lock for tracking file after ${lock_timeout} seconds${NC}" >&2
        exec 200>&-  # Close the file descriptor
        return 1
    fi

    if [ ! -f "$TRACKING_FILE" ]; then
        # Create initial tracking file
        cat > "$TRACKING_FILE" << EOF
{
  "branches": {},
  "last_updated": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
}
EOF
    fi

    # Update tracking file with a single jq command using --slurpfile for comments
    local temp_file=$(mktemp "${TMPDIR:-/tmp}/review-status-temp.XXXXXX")
    TEMP_FILES+=("$temp_file")

    local comments_source_file="$comments_file"
    if [[ -z "$comments_file" ]]; then
        comments_source_file="/dev/null"
    fi
    
    if jq --arg branch "$branch_name" \
          --arg pr "$pr_number" \
          --arg status "$review_status" \
          --arg updated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
          --arg pr_state "$pr_state" \
          --slurpfile new_comments "$comments_source_file" ' 
           # Update global timestamp
           .last_updated = $updated |
           # Initialize branch if it does not exist
           .branches[$branch] |= (
            . // {pr_number: ($pr | tonumber? // $pr), comments: []}
           ) |
           # Update review status and timestamp for the branch
           .branches[$branch].review_status = $status |
           .branches[$branch].last_updated = $updated |
           # Update comments list
           .branches[$branch].comments = (
             if $pr_state != "open" then
               # Clear all comments for closed PRs
               []
             elif ($new_comments | length) > 0 then
               # Combine existing comments with new ones, avoiding duplicates by ID
               (.branches[$branch].comments // []) + 
               ($new_comments[0] | map({id: .id, status: "todo", body: .body, created_at: .submitted_at})) |
               unique_by(.id)
             else
               # Keep existing comments if no new ones are provided
               .branches[$branch].comments // []
             end
           )' \
          "$TRACKING_FILE" > "$temp_file"; then
        mv "$temp_file" "$TRACKING_FILE"
        echo -e "${GREEN}Updated tracking file: $TRACKING_FILE${NC}" >&2
    else
        echo -e "${RED}Error: Failed to update tracking file${NC}" >&2
        rm -f "$temp_file"
        exec 200>&-  # Close the file descriptor
        return 1
    fi
    
    exec 200>&-  # Close the file descriptor
}

# Main function
main() {
    local input=""
    local wait_for_comments="false"
    local max_polls=5  # Default maximum number of polling attempts
    local poll_interval="$DEFAULT_POLL_INTERVAL"
    
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
                if [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]]; then
                    poll_interval="$2"
                    shift 2
                else
                    echo -e "${RED}Error: --poll-interval requires a numeric argument${NC}" >&2
                    exit 1
                fi
                ;;
            --max-polls)
                if [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]]; then
                    max_polls="$2"
                    shift 2
                else
                    echo -e "${RED}Error: --max-polls requires a numeric argument${NC}" >&2
                    exit 1
                fi
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
        echo -e "${BLUE}Checking PR #${pr_number}${NC}" >&2
        # Get PR details when PR number is provided directly
        local pr_info=$(github_api_request "/pulls/$pr_number")
        pr_title=$(echo "$pr_info" | jq -r '.title')
        pr_state=$(echo "$pr_info" | jq -r '.state')
    else
        branch_name="$input"
        echo -e "${BLUE}Checking branch: ${branch_name}${NC}" >&2
        local pr_info
        if ! pr_info=$(get_pr_info_from_branch "$branch_name"); then
            echo -e "${RED}Error: Failed to fetch PR information for branch: ${branch_name}${NC}" >&2
            exit 1
        fi
        
        if [ -z "$pr_info" ]; then
            echo -e "${RED}No open PR found for branch: ${branch_name}${NC}" >&2
            echo "{\"status\": \"None\", \"comments\": 0}"
            # Update tracking file to clear comments for closed PR
            if ! update_tracking_file "$branch_name" "" "None" "" "closed"; then
                echo -e "${RED}Error: Failed to update tracking file. Exiting.${NC}" >&2
                exit 1
            fi
            exit 2
        fi
        
        pr_number=$(echo "$pr_info" | jq -r '.number')
        pr_title=$(echo "$pr_info" | jq -r '.title')
        pr_state=$(echo "$pr_info" | jq -r '.state')
    fi
    
    # Check review status
    local review_status
    review_status=$(check_pr_review_status "$pr_number" "$wait_for_comments" "$poll_interval" "$max_polls" "$pr_title" "$pr_state")
    local check_status_exit_code=$?
    
    # Update tracking file if branch name was provided
    if [ -n "$branch_name" ]; then
        local clean_status=$(echo "$review_status" | jq -r '.status')
        
        local comments_file=""
        if [ "$(echo "$review_status" | jq -r '.comments')" -gt 0 ]; then
            comments_file="comments_${pr_number}.json"
        fi
        
        # Note: Comment clearing for closed PRs is handled in update_tracking_file function
        # based on pr_state, so we don't need to modify clean_status or comments_file here
        
        if ! update_tracking_file "$branch_name" "$pr_number" "$clean_status" "$comments_file" "$pr_state"; then
            echo -e "${RED}Error: Failed to update tracking file. Exiting.${NC}" >&2
            exit 1
        fi
    fi
    
    echo "$review_status" | jq .

    if [ "$check_status_exit_code" -ne 0 ]; then
        exit "$check_status_exit_code"
    fi
}

# Run main function with all arguments
main "$@"

