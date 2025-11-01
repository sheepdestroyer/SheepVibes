#!/bin/bash

# trigger-review.sh - Post a /gemini review comment to a PR
# Usage: ./trigger-review.sh [pr-number]

set -e

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
GITHUB_API_BASE="https://api.github.com"

# Function to print usage
usage() {
    echo "Usage: $0 [pr-number]"
    echo ""
    echo "Example:"
    echo "  $0 123"
    echo ""
    echo "This script posts a /gemini review comment to a given PR number."
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
    local method="$2"
    local data="$3"
    local url="${GITHUB_API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}${endpoint}"
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        local response
        local http_code
        local headers_file=$(mktemp)
        
        if [ -z "$GITHUB_TOKEN" ]; then
            echo -e "${YELLOW}Warning: GITHUB_TOKEN not set. Using unauthenticated requests (rate limited).${NC}" >&2
            response=$(curl -s -w "\n%{http_code}" -D "$headers_file" -X "$method" -H "Accept: application/vnd.github.v3+json" -d "$data" "$url")
        else
            response=$(curl -s -w "\n%{http_code}" -D "$headers_file" -X "$method" -H "Authorization: token $GITHUB_TOKEN" \
                 -H "Accept: application/vnd.github.v3+json" -d "$data" \
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
        if [ "$http_code" = "201" ]; then
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

# Main function
main() {
    local pr_number=""
    
    # Parse command line arguments
    if [ $# -ne 1 ]; then
        usage
        exit 1
    fi
    
    pr_number="$1"
    
    check_dependencies
    
    # Post the comment
    local comment_data='{"body": "/gemini review"}'
    github_api_request "/issues/${pr_number}/comments" "POST" "$comment_data"
}

# Run main function with all arguments
main "$@"
