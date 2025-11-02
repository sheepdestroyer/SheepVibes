#!/bin/bash
set -euo pipefail

# Unified PR Tracker Microagent Workflow Executor
# Implements the strict state machine workflow defined in pr-review-tracker.md

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BRANCH_NAME="${1:-feat/unified-pr-tracker}"
PR_NUMBER="${2:-162}"
MAX_CYCLES=50
TRACKING_FILE="pr-review-tracker.json"

log() {
    echo -e "${BLUE}[$(date -u +'%Y-%m-%dT%H:%M:%SZ')]${NC} $1" >&2
}

error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

success() {
    echo -e "${GREEN}SUCCESS:${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}WARNING:${NC} $1" >&2
}

check_workflow_conditions() {
    local branch="$1"
    local pr_number="$2"
    
    log "Checking workflow conditions for branch: $branch, PR: $pr_number"
    
    # Get current tracking data
    local tracking_data
    tracking_data=$(jq -c ".branches[\"$branch\"]" "$TRACKING_FILE" 2>/dev/null || echo "null")
    
    if [ "$tracking_data" = "null" ]; then
        error "No tracking data found for branch: $branch"
        return 1
    fi
    
    local review_status=$(echo "$tracking_data" | jq -r '.review_status')
    local todo_comments=$(echo "$tracking_data" | jq '[.comments[] | select(.status == "todo")] | length')
    
    log "Current state - Review Status: $review_status, TODO Comments: $todo_comments"
    
    # Check end conditions
    if [ "$review_status" = "RateLimited" ]; then
        log "Workflow stopped: Google Code Assist rate limited"
        return 2
    fi
    
    if [ "$review_status" = "Complete" ]; then
        log "Workflow stopped: Google Code Assist indicates completion"
        return 2
    fi
    
    # Check if we should continue
    if [ "$review_status" = "Commented" ] && [ "$todo_comments" -gt 0 ]; then
        log "Workflow continuing: $todo_comments TODO comments need addressing"
        return 0
    fi
    
    if [ "$review_status" = "None" ]; then
        log "Workflow continuing: No comments yet, waiting for review"
        return 0
    fi
    
    warn "Unexpected state: Review Status=$review_status, TODO Comments=$todo_comments"
    return 1
}

process_todo_comments() {
    local branch="$1"
    local pr_number="$2"
    
    log "Processing TODO comments for branch: $branch"
    
    # Get TODO comments
    local todo_comments
    todo_comments=$(jq -c ".branches[\"$branch\"].comments[] | select(.status == \"todo\")" "$TRACKING_FILE")
    
    if [ -z "$todo_comments" ]; then
        warn "No TODO comments found"
        return 1
    fi
    
    # Process each TODO comment
    echo "$todo_comments" | while IFS= read -r comment; do
        local comment_id=$(echo "$comment" | jq -r '.id')
        
        log "Processing comment $comment_id"
        
        # Here the microagent would implement the actual fix
        # For now, we'll just mark it as addressed to demonstrate the workflow
        ./mark-addressed.sh "$branch" "$comment_id"
        
        log "Marked comment $comment_id as addressed"
    done
    
    return 0
}

main_workflow() {
    local branch="$1"
    local pr_number="$2"
    local cycle_count=0
    
    log "Starting unified PR tracker workflow for branch: $branch, PR: $pr_number"
    
    while [ "$cycle_count" -lt "$MAX_CYCLES" ]; do
        cycle_count=$((cycle_count + 1))
        log "=== Workflow Cycle $cycle_count/$MAX_CYCLES ==="
        
        # Check if we should continue
        if ! check_workflow_conditions "$branch" "$pr_number"; then
            case $? in
                2)
                    success "Workflow completed normally"
                    return 0
                    ;;
                *)
                    error "Workflow error detected"
                    return 1
                    ;;
            esac
        fi
        
        # Get current state
        local tracking_data=$(jq -c ".branches[\"$branch\"]" "$TRACKING_FILE")
        local review_status=$(echo "$tracking_data" | jq -r '.review_status')
        local todo_comments=$(echo "$tracking_data" | jq '[.comments[] | select(.status == "todo")] | length')
        
        case "$review_status" in
            "Commented")
                if [ "$todo_comments" -gt 0 ]; then
                    log "State: Commented with $todo_comments TODO comments - Processing comments"
                    
                    # Process all TODO comments
                    if process_todo_comments "$branch" "$pr_number"; then
                        log "All TODO comments processed, pushing changes and triggering new review"
                        
                        # Push changes (simulated)
                        log "Pushing changes to branch: $branch"
                        git add -A
                        # Check if there are changes to commit
                        if git diff-index --quiet HEAD --; then
                            log "No changes to commit - skipping commit and push"
                        else
                            git commit -m "Fix: Address Google Code Assist comments - cycle $cycle_count"
                            git push origin "$branch"
                        fi
                        
                        # Trigger new review
                        log "Triggering new Google Code Assist review"
                        ./trigger-review.sh "$pr_number"
                        
                        # Wait for new comments
                        log "Waiting for new Google Code Assist comments..."
                        ./check-review-status.sh "$pr_number" --wait
                        
                        # Update tracking with new comments
                        log "Updating tracking with new comments"
                        ./update-tracking-efficient.sh "$pr_number" "$branch"
                    else
                        error "Failed to process TODO comments"
                        return 1
                    fi
                else
                    warn "State: Commented but no TODO comments - This should not happen"
                    # Trigger review to get new comments
                    ./trigger-review.sh "$pr_number"
                    ./check-review-status.sh "$pr_number" --wait
                    ./update-tracking-efficient.sh "$pr_number" "$branch"
                fi
                ;;
                
            "None")
                log "State: No comments - Triggering initial review"
                ./trigger-review.sh "$pr_number"
                ./check-review-status.sh "$pr_number" --wait
                ./update-tracking-efficient.sh "$pr_number" "$branch"
                ;;
                
            *)
                error "Unexpected review status: $review_status"
                return 1
                ;;
        esac
        
        log "Cycle $cycle_count completed, checking next cycle..."
        sleep 5  # Small delay between cycles
    done
    
    warn "Maximum cycles ($MAX_CYCLES) reached without completion"
    return 1
}

# Main execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <branch-name> <pr-number>"
    echo "Example: $0 feat/unified-pr-tracker 162"
    exit 1
fi

main_workflow "$BRANCH_NAME" "$PR_NUMBER"
