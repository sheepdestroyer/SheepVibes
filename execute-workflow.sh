#!/bin/bash
set -euo pipefail

# Unified PR Tracker Microagent Workflow Executor
# Implements the strict state machine workflow defined in pr-review-tracker.md

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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

# Function to implement actual fixes for TODO comments
implement_fixes() {
    local branch="$1"
    local pr_number="$2"
    local changes_made=false
    
    log "Implementing fixes for TODO comments on branch: $branch"
    
    # Process each TODO comment individually
    while read -r comment; do
        local body=$(echo "$comment" | jq -r '.body')

        # Extract all code blocks from the comment body
        local code_blocks=$(echo "$body" | sed -n '/^```diff/,/^```/p' | sed '1d;$d')

        if [ -z "$code_blocks" ]; then
            warn "No diff code blocks found in comment. Skipping."
            continue
        fi

        # Apply the patch
        local patch_file=$(mktemp)
        TEMP_FILES+=("$patch_file")
        echo -e "$code_blocks" > "$patch_file"
        if git apply --check "$patch_file"; then
            if git apply "$patch_file"; then
                success "Successfully applied patch from a comment."
                changes_made=true
            else
                error "Failed to apply patch from a comment."
            fi
        else
            error "Patch check failed for a comment."
        fi
    done < <(jq -c ".branches[\"$branch\"].comments[] | select(.status == \"todo\")" "$TRACKING_FILE")
    
    if [ "$changes_made" = true ]; then
        log "Committing applied fixes..."
        git add -u
        git commit -m "feat: Apply automated code review fixes"
        return 0
    else
        warn "No changes were made by the microagent."
        return 1
    fi
}

# Complete workflow for processing TODO comments with all required steps
process_todo_comments() {
    local branch="$1"
    local pr_number="$2"
    
    log "Starting complete TODO comment processing workflow for branch: $branch"
    
    # Step 1: Implement actual fixes
    if ! implement_fixes "$branch" "$pr_number"; then
        error "Failed to implement fixes for TODO comments"
        return 1
    fi
    
    # Step 2: Get all TODO comment IDs to mark as addressed
    local todo_comment_ids_array
    mapfile -t todo_comment_ids_array < <(jq -r ".branches[\"$branch\"].comments[] | select(.status == \"todo\") | .id" "$TRACKING_FILE")

    if [ ${#todo_comment_ids_array[@]} -eq 0 ]; then
        warn "No TODO comments found to mark as addressed"
        return 1
    fi

    # Step 3: Mark all TODO comments as addressed
    log "Marking comments as addressed: ${todo_comment_ids_array[*]}"
    if ! ./mark-addressed.sh "$branch" "${todo_comment_ids_array[@]}"; then
        error "Failed to mark comments as addressed"
        return 1
    fi
    
    # Step 4: Push changes to branch (simulated - in real workflow would commit and push)
    log "SIMULATION: Changes would be committed and pushed to branch: $branch"
    warn "In real workflow: git commit and git push would happen here"
    
    # Step 5: Trigger new review
    log "Triggering new Google Code Assist review for PR: $pr_number"
    if ! ./trigger-review.sh "$pr_number"; then
        error "Failed to trigger new review"
        return 1
    fi
    
    success "Complete TODO comment processing workflow finished"
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
                    
                    # Process all TODO comments and continue workflow
                    if process_todo_comments "$branch" "$pr_number"; then
                        success "TODO comments processed successfully - workflow continuing"
                        # Continue to next cycle to check for new comments
                    else
                        error "Failed to process TODO comments - workflow halted"
                        return 1
                    fi
                else
                    # Handle Commented state with no TODO comments and None state
                    if [ "$review_status" = "Commented" ]; then
                        warn "State: Commented but no TODO comments - This state should not trigger new reviews"
                        log "Checking if this indicates workflow completion..."
                        # Check if we should update status to Complete
                        ./check-review-status.sh "$branch" > /dev/null
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
                        ./check-review-status.sh "$branch" --wait > /dev/null
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
