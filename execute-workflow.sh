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
BRANCH_NAME="$1"
PR_NUMBER="$2"
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
        log "Workflow paused: Google Code Assist rate limited - will retry after waiting"
        return 3  # Special code for rate limit pause
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
    
    # Process each TODO comment - MICROAGENT MUST IMPLEMENT ACTUAL FIXES
    echo "$todo_comments" | while IFS= read -r comment; do
        local comment_id=$(echo "$comment" | jq -r '.id')
        local comment_body=$(echo "$comment" | jq -r '.body')
        
        log "Processing comment $comment_id: $comment_body"
        
        # CRITICAL: Microagent must implement actual fixes here
        # This is where the AI agent reads the comment and makes code changes
        # For now, we'll log the comment but NOT mark it as addressed
        # until actual fixes are implemented
        
        warn "TODO: Implement actual fix for comment $comment_id"
        warn "Comment: $comment_body"
        
        # DO NOT mark as addressed until actual fixes are implemented
        # ./mark-addressed.sh "$branch" "$comment_id"
    done
    
    warn "No actual fixes implemented - this is a simulation. Workflow will continue."
    return 0
}

main_workflow() {
    local branch="$1"
    local pr_number="$2"
    local cycle_count=0
    local consecutive_same_state=0
    local last_state=""
    
    log "Starting unified PR tracker workflow for branch: $branch, PR: $pr_number"
    
    while [ "$cycle_count" -lt "$MAX_CYCLES" ]; do
        cycle_count=$((cycle_count + 1))
        log "=== Workflow Cycle $cycle_count/$MAX_CYCLES ==="
        
        # CRITICAL: Always refresh PR state at the beginning of each cycle
        # and wait for the update to complete before checking conditions
        log "Refreshing PR state from GitHub..."
        if ! ./check-review-status.sh "$branch" > /dev/null 2>&1; then
            error "Failed to refresh PR state from GitHub"
            return 1
        fi
        
        # Small delay to ensure tracking file is updated
        sleep 2
        
        # Check if we should continue with freshly updated state
        check_workflow_conditions "$branch" "$pr_number"
        local condition_result=$?

        case "$condition_result" in
            0|3) # Continue workflow for normal operation or rate limiting
                ;;
            2) # Workflow complete
                success "Workflow completed normally"
                return 0
                ;;
            1) # Error
                error "Workflow error detected"
                return 1
                ;;
        esac
        
        # Get current state
        local tracking_data=$(jq -c ".branches[\"$branch\"]" "$TRACKING_FILE")
        local review_status=$(echo "$tracking_data" | jq -r '.review_status')
        local todo_comments=$(echo "$tracking_data" | jq '[.comments[] | select(.status == "todo")] | length')
        
        # Track state changes to prevent infinite loops
        if [ "$review_status" = "$last_state" ]; then
            consecutive_same_state=$((consecutive_same_state + 1))
        else
            consecutive_same_state=0
            last_state="$review_status"
        fi
        
        # Prevent infinite loops in same state
        if [ "$consecutive_same_state" -gt 10 ]; then
            error "Stuck in state '$review_status' for 10+ cycles - workflow terminated"
            return 1
        fi
        
        log "Current State - Review: $review_status, TODO Comments: $todo_comments, Same State Cycles: $consecutive_same_state"
        
        case "$review_status" in
            "Commented"|"None")
                # Handle Commented state with TODO comments
                if [ "$review_status" = "Commented" ] && [ "$todo_comments" -gt 0 ]; then
                    log "State: Commented with $todo_comments TODO comments - Processing comments"
                    
                    # Process all TODO comments and then halt for the agent to work.
                    process_todo_comments "$branch" "$pr_number"
                    error "CRITICAL: Microagent must implement actual fixes for the comments listed above before continuing. Halting workflow."
                    return 1
                else
                    # Handle Commented state with no TODO comments and None state
                    if [ "$review_status" = "Commented" ]; then
                        warn "State: Commented but no TODO comments - This state should not trigger new reviews"
                        log "Checking if this indicates workflow completion..."
                        # Check if we should update status to Complete
                        ./check-review-status.sh "$branch"
                        # After updating, check if we should transition to Complete
                        sleep 2  # Small delay to ensure file is updated
                        local new_tracking_data=$(jq -c ".branches[\"$branch\"]" "$TRACKING_FILE")
                        local new_review_status=$(echo "$new_tracking_data" | jq -r '.review_status')
                        if [ "$new_review_status" = "Complete" ]; then
                            success "Workflow completed: All comments addressed and Google Code Assist indicates completion"
                            return 0
                        elif [ "$new_review_status" = "RateLimited" ]; then
                            log "Google Code Assist rate limited - workflow paused"
                            sleep "${RATE_LIMIT_CHECK_INTERVAL:-60}"
                        else
                            log "Still in Commented state - waiting for Google Code Assist completion signal"
                            sleep 10  # Wait before checking again
                        fi
                    else
                        log "State: No comments - Triggering initial review"
                        ./trigger-review.sh "$pr_number"
                        ./check-review-status.sh "$branch" --wait
                    fi
                fi
                ;;
                
            "RateLimited")
                log "State: Rate limited - Waiting 1 minute before retry"
                sleep "${RATE_LIMIT_CHECK_INTERVAL:-60}"
                # Check if rate limit has cleared and update tracking file
                ./check-review-status.sh "$branch"
                ;;
                
            *)
                error "Unexpected review status: $review_status"
                return 1
                ;;
        esac
        
        log "Cycle $cycle_count completed, checking next cycle..."
        sleep "${WORKFLOW_CYCLE_DELAY:-5}"  # Small delay between cycles, configurable via WORKFLOW_CYCLE_DELAY
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
