
#!/bin/bash

# Common functions for SheepVibes scripts

# Set default GitHub API base URL
GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Robust GitHub API request function with rate limiting and retry logic
github_api_request() {
    local endpoint="$1"
    local url="${GITHUB_API_BASE}/repos/${REPO_OWNER}/${REPO_NAME}${endpoint}"
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        local response
        local http_code
        local headers_file=$(mktemp "${TMPDIR:-/tmp}/review-status-headers.XXXXXX")
        TEMP_FILES+=("$headers_file")
        
        local auth_header=()
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            auth_header=("-H" "Authorization: token $GITHUB_TOKEN")
        else
            echo -e "${YELLOW}Warning: GITHUB_TOKEN not set. Using unauthenticated requests (rate limited).${NC}" >&2
        fi

        response=$(curl -s -w "\n%{http_code}" -D "$headers_file" \
             -H "Accept: application/vnd.github.v3+json" \
             "${auth_header[@]}" \
             "$url")
        
        http_code=$(echo "$response" | tail -n1)
        local response_body=$(echo "$response" | head -n -1)
        
        # Check for rate limiting (HTTP 429 or 403 with rate limit message)
        if [ "$http_code" = "429" ] || { [ "$http_code" = "403" ] && echo "$response_body" | grep -iq "API rate limit exceeded"; }; then
            local reset_time
            reset_time=$(grep -i "x-ratelimit-reset" "$headers_file" | cut -d' ' -f2 | tr -d '\r')
            
            if [ -n "$reset_time" ]; then
                local current_time=$(date +%s)
                local wait_time=$((reset_time - current_time + 10))  # Add 10 seconds buffer
                
                if [ "$wait_time" -gt 0 ]; then
                    echo -e "${YELLOW}Rate limit hit. Waiting ${wait_time} seconds...${NC}" >&2
                    sleep "$wait_time"
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
            sleep "$backoff_time"
        fi
    done
    
    echo -e "${RED}Failed to make GitHub API request after ${max_retries} attempts${NC}" >&2
    return 1
}

# Get repository owner and name from git remote
get_repo_info() {
    local repo_slug
    
    # Use environment variables if provided, otherwise detect from git remote
    if [ -n "${GITHUB_REPO_OWNER:-}" ] && [ -n "${GITHUB_REPO_NAME:-}" ]; then
        REPO_OWNER="$GITHUB_REPO_OWNER"
        REPO_NAME="$GITHUB_REPO_NAME"
    else
        REPO_SLUG=$(git remote get-url origin 2>/dev/null | sed -e 's/.*github.com[:\/]//' -e 's/\.git$//')
        if [ -n "$REPO_SLUG" ]; then
            REPO_OWNER=$(echo "$REPO_SLUG" | cut -d'/' -f1)
            REPO_NAME=$(echo "$REPO_SLUG" | cut -d'/' -f2)
        else
            printf "Error: Could not determine repository owner and name from git remote.\n" >&2
            exit 1
        fi
    fi
    REPO="${REPO_OWNER}/${REPO_NAME}"
    export REPO_OWNER REPO_NAME REPO
}

