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
Usage: $0 [pr-number] [--wait|--continue [max-rounds]]

Triggers Google Code Assist review by posting "/gemini review" comment to a PR.

Options:
  --wait           Wait for review completion and check status
  --continue       Automatically continue review-fix cycles until no issues remain
  max-rounds       Maximum number of review cycles (default: 10)

Example:
  $0 162
  $0 162 --wait
  $0 162 --continue
  $0 162 --continue 5
EOF
}

# Parse command line arguments
if [ $# -lt 1 ] || [ $# -gt 3 ]; then
    usage
    exit 1
fi

PR_NUMBER="$1"
WAIT_FOR_REVIEW=false
CONTINUE_CYCLE=false
MAX_ROUNDS=10

if [ $# -ge 2 ]; then
    case "$2" in
        --wait)
            WAIT_FOR_REVIEW=true
            ;;
        --continue)
            CONTINUE_CYCLE=true
            if [ $# -eq 3 ] && [[ "$3" =~ ^[0-9]+$ ]]; then
                MAX_ROUNDS="$3"
            fi
            ;;
        *)
            usage
            exit 1
            ;;
    esac
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
    max_wait=300  # 5 minutes
    wait_interval=30  # 30 seconds
    elapsed=0
    
    while [ $elapsed -lt $max_wait ]; do
        sleep $wait_interval
        elapsed=$((elapsed + wait_interval))
        
        # Check review status using the check-review-status script
        echo -e "${BLUE}Checking review status... (${elapsed}s elapsed)${NC}"
        review_status=$(bash check-review-status.sh "$PR_NUMBER" | grep -E "^(None|Started|Commented)$" | head -1)
        
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
elif [ "$CONTINUE_CYCLE" = true ]; then
    echo -e "${BLUE}Starting automated review-fix cycle (max rounds: $MAX_ROUNDS)...${NC}"
    
    current_round=1
    while [ $current_round -le $MAX_ROUNDS ]; do
        echo -e "${BLUE}=== Round $current_round/$MAX_ROUNDS ===${NC}"
        
        # Wait for review completion
        echo -e "${BLUE}Waiting for Google Code Assist review...${NC}"
        max_wait=600  # 10 minutes per round
        wait_interval=30
        elapsed=0
        review_completed=false
        
        while [ $elapsed -lt $max_wait ]; do
            sleep $wait_interval
            elapsed=$((elapsed + wait_interval))
            
            review_status=$(bash check-review-status.sh "$PR_NUMBER" | grep -E "^(None|Started|Commented)$" | head -1)
            
            if [ "$review_status" = "Commented" ] || [ "$review_status" = "None" ]; then
                review_completed=true
                break
            fi
        done
        
        if [ "$review_completed" = false ]; then
            echo -e "${YELLOW}Review did not complete within ${max_wait}s timeout in round $current_round${NC}"
            exit 1
        fi
        
        # Check if no issues remain
        if [ "$review_status" = "None" ]; then
            echo -e "${GREEN}✓ Google Code Assist review completed - no issues found${NC}"
            echo -e "${GREEN}All review cycles completed successfully!${NC}"
            exit 0
        fi
        
        # Check comments for "No remaining issues" or similar
        comments_file="comments_${PR_NUMBER}.json"
        if [ -f "$comments_file" ]; then
            no_issues_found=$(jq -r '.[] | select(.body | test("no.*remaining.*issue|no.*issue.*remaining|all.*issue.*resolved|all.*fixed"; "i")) | .body' "$comments_file" 2>/dev/null | head -1)
            if [ -n "$no_issues_found" ]; then
                echo -e "${GREEN}✓ Google Code Assist confirmed no remaining issues${NC}"
                echo -e "${GREEN}All review cycles completed successfully!${NC}"
                exit 0
            fi
        fi
        
        echo -e "${YELLOW}Issues found in round $current_round. The microagent will address them and push changes.${NC}"
        echo -e "${BLUE}Waiting 60 seconds for microagent to address issues and push changes...${NC}"
        sleep 60
        
        # Check if new commits were pushed before triggering next review
        echo -e "${BLUE}Checking for new commits...${NC}"
        git fetch origin
        local_commit=$(git rev-parse HEAD)
        remote_commit=$(git rev-parse origin/feat/unified-pr-tracker)
        
        if [ "$local_commit" = "$remote_commit" ]; then
            echo -e "${YELLOW}No new commits detected. Microagent may still be working or no changes needed.${NC}"
            echo -e "${BLUE}Waiting additional 30 seconds...${NC}"
            sleep 30
        else
            echo -e "${GREEN}New commits detected! Proceeding with next review cycle.${NC}"
        fi

        # Trigger next review cycle
        echo -e "${BLUE}Triggering next review cycle...${NC}"
        curl -s -X POST \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github.v3+json" \
            -H "Content-Type: application/json" \
            -d '{"body": "/gemini review"}' \
            "$GITHUB_API/repos/$REPO/issues/$PR_NUMBER/comments" > /dev/null
        
        current_round=$((current_round + 1))
    done
    
    echo -e "${YELLOW}Maximum rounds ($MAX_ROUNDS) reached. Manual review may be needed.${NC}"
    exit 0
else
    echo -e "${GREEN}Google Code Assist review has been triggered. Use './trigger-review.sh $PR_NUMBER --wait' to wait for completion.${NC}"
fi
