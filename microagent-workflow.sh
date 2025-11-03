#!/bin/bash
set -euo pipefail

# Microagent-driven PR Review Workflow
# Strictly enforces the state machine workflow for Google Code Assist reviews

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Configuration
TRACKING_FILE="pr-review-tracker.json"
MAX_CYCLES=50
RATE_LIMIT_CHECK_INTERVAL=60

# Check if required tools are available
check_dependencies() {
    local deps=("jq" "git" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' not found"
            return 1
        fi
    done
    return 0
}

# Get current workflow state
get_workflow_state() {
    local branch="$1"
    
    if [ ! -f "$TRACKING_FILE" ]; then
        error "Tracking file not found: $TRACKING_FILE"
        return 1
    fi
    
    local tracking_data
    tracking_data=$(jq -c ".branches[\"$branch\"]" "$TRACKING_FILE" 2>/dev/null || echo "{}")
    
    if [ "$tracking_data" = "null" ] || [ "$tracking_data" = "{}" ]; then
        error "No tracking data found for branch: $branch"
        return 1
    fi
    
    local review_status=$(echo "$tracking_data" | jq -r '.review_status // "None"')
    local todo_comments=$(echo "$tracking_data" | jq '[.comments[]? | select(.status == "todo")] | length // 0')
    local pr_number=$(echo "$tracking_data" | jq -r '.pr_number // ""')
    
    echo "$review_status|$todo_comments|$pr_number"
}

# Strict State Machine Workflow
microagent_workflow() {
    local branch="$1"
    local pr_number="$2"
    local cycle_count=0
    
    log "Starting microagent-driven workflow for branch: $branch, PR: $pr_number"
    
    while [ "$cycle_count" -lt "$MAX_CYCLES" ]; do
        cycle_count=$((cycle_count + 1))
        log "=== Microagent Workflow Cycle $cycle_count/$MAX_CYCLES ==="
        
        # Get current state
        local state_info
        state_info=$(get_workflow_state "$branch")
        if [ $? -ne 0 ]; then
            error "Failed to get workflow state"
            return 1
        fi
        
        IFS='|' read -r review_status todo_comments current_pr <<< "$state_info"
        
        log "Current State - Review: $review_status, TODO Comments: $todo_comments, PR: $current_pr"
        
        # Strict State Machine Logic
        case "$review_status" in
            "Complete")
                success "Workflow completed: Google Code Assist indicates no further issues"
                return 0
                ;;
                
            "RateLimited")
                warn "Google Code Assist rate limited - checking if we should continue"
                
                # Check if we have actionable comments to address
                if [ "$todo_comments" -gt 0 ]; then
                    log "Rate limited but $todo_comments TODO comments exist - waiting for rate limit to clear"
                    sleep "$RATE_LIMIT_CHECK_INTERVAL"
                    ./check-review-status.sh "$branch"
                else
                    warn "Rate limited with no TODO comments - workflow may be complete"
                    # Check if this is a stable state (no comments for 24 hours)
                    local last_updated=$(jq -r ".branches[\"$branch\"].last_updated" "$TRACKING_FILE")
                    local current_time=$(date -u +%s)
                    local last_updated_time=$(date -u -d "$last_updated" +%s 2>/dev/null || echo 0)
                    local time_diff=$((current_time - last_updated_time))
                    
                    if [ "$time_diff" -gt 86400 ]; then # 24 hours
                        success "Workflow complete: Rate limited for 24+ hours with no new comments"
                        return 0
                    else
                        log "Rate limited recently - continuing to wait"
                        sleep "$RATE_LIMIT_CHECK_INTERVAL"
                        ./check-review-status.sh "$branch"
                    fi
                fi
                ;;
                
            "Commented")
                if [ "$todo_comments" -gt 0 ]; then
                    log "State: Commented with $todo_comments TODO comments"
                    error "CRITICAL: Microagent must implement fixes for TODO comments before continuing"
                    error "Use: ./mark-addressed.sh '$branch' <comment_ids> after implementing fixes"
                    return 1
                else
                    warn "State: Commented but no TODO comments - checking completion status"
                    # This might indicate workflow completion
                    # Trigger one final check to see if status updates to Complete
                    ./check-review-status.sh "$branch"
                fi
                ;;
                
            "None")
                log "State: No comments - triggering initial review"
                ./trigger-review.sh "$pr_number"
                ./check-review-status.sh "$branch" --wait
                ;;
                
            *)
                error "Unexpected review status: $review_status"
                return 1
                ;;
        esac
        
        log "Cycle $cycle_count completed"
        sleep 5  # Small delay between cycles
    done
    
    warn "Maximum cycles ($MAX_CYCLES) reached without completion"
    return 1
}

# Usage
usage() {
    echo "Usage: $0 <branch-name> <pr-number>"
    echo "Strict microagent-driven workflow for Google Code Assist reviews"
    echo ""
    echo "This workflow strictly enforces the state machine rules:"
    echo "- Only one review trigger per cycle"
    echo "- All TODO comments must be addressed before new reviews"
    echo "- Proper handling of rate limits and completion conditions"
    echo ""
    echo "Example: $0 feat/unified-pr-tracker 163"
}

# Main execution
main() {
    if [ $# -ne 2 ]; then
        usage
        exit 1
    fi
    
    local branch="$1"
    local pr_number="$2"
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Check if tracking file exists
    if [ ! -f "$TRACKING_FILE" ]; then
        error "Tracking file not found: $TRACKING_FILE"
        error "Run check-review-status.sh first to initialize tracking"
        exit 1
    fi
    
    # Run microagent workflow
    microagent_workflow "$branch" "$pr_number"
}

main "$@"
