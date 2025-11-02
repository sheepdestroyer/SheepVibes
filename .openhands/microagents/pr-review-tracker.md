---
triggers:
- review-cycle
- pr-review
- code-review
- google-code-assist
agent: CodeActAgent
---

# PR Review Tracker Microagent

This microagent provides a comprehensive system for tracking and managing GitHub PR code reviews with Google Code Assist integration, replacing the previous code-review-cycle and pr-ready-review microagents.

## Purpose

Track and manage GitHub PR code reviews through a simplified workflow that eliminates the need to close/reopen PRs for fresh reviews. The review can be triggered either manually by a developer or automatically by the microagent using `/gemini review` comment after each push.

## Core Principles

1. **Global Tracking**: Maintain a dedicated global file (`pr-review-tracker.json`) with sections for each working branch
2. **Review Status Tracking**: Track Google Code Assist review status (None, Commented) for each PR
3. **Comment Management**: Track individual review comments with status (todo, addressed)
4. **Comment-Based Trigger**: Trigger Google Code Assist using `/gemini review` comment after each push instead of closing/reopening PRs
5. **Ready to Review**: Always mark PRs as ready to review immediately after creation

## Global Tracking File Structure

The `pr-review-tracker.json` file maintains state for all working branches:

```json
{
  "branches": {
    "feat/new-feature": {
      "pr_number": 123,
      "review_status": "Commented",
      "last_updated": "2024-10-31T23:25:00Z",
      "comments": [
        {
          "id": 987654321,
          "status": "todo",
          "body": "Consider adding error handling here",
          "created_at": "2024-10-31T23:20:00Z"
        }
      ]
    }
  },
  "last_updated": "2024-10-31T23:25:00Z"
}
```

## Review Status Definitions

- **None**: No Google Code Assist comments detected
- **Commented**: Comments have been provided and need addressing
- **Complete**: All comments have been addressed and no further action needed
- **RateLimited**: Google Code Assist has reached daily quota limit

## Tools and Scripts

### check-review-status.sh

This script checks the current Google Code Assist review status for a branch or PR and returns a JSON object with the status and comment count.

```bash
# Usage: ./check-review-status.sh [branch-name|pr-number] [--wait] [--poll-interval SECONDS]
```

**Features**:
- Checks Google Code Assist review status (`None`, `Commented`, `Complete`, `RateLimited`)
- With `--wait` flag, polls for comments until they are available
- Returns a JSON object with the review status and the number of comments

**Output Format**:
```json
{
  "status": "Commented",
  "comments": 5
}
```

**Exit Codes**:
- `0`: Success with review status output (including when no open PR is found)
- `1`: Error occurred

**Note**: A new Google Code Assist review can be triggered by posting a `/gemini review` comment. This can be done automatically using the `trigger-review.sh` script, or manually in the GitHub PR interface.

## Error Handling

- **Authentication issues**: Update remote URL with current GITHUB_TOKEN
- **Branch conflicts**: Create new unique branch names
- **No comments received**: After waiting the maximum poll time (5 polls with intervals starting at 120 seconds and increasing by 30 seconds each poll, for a total of 15 minutes), proceed with manual code review
- **API rate limits**: Script implements automatic rate limit handling with exponential backoff
- **Google Code Assist daily quota**: Workflow continues if new comments exist after rate limit warning or 24 hours have passed

### trigger-review.sh

This script triggers a new Google Code Assist review by posting a `/gemini review` comment to the specified PR.

```bash
# Usage: ./trigger-review.sh [pr-number]
```

### update-tracking-efficient.sh

This script updates the tracking file with new comments from a JSON file. It serves a distinct purpose from the `update_tracking_file` function in `check-review-status.sh`:

- **Primary Use Case**: Manual synchronization of the tracking file when comments are fetched separately
- **Batch Processing**: Useful for bulk updates when multiple comment files need to be processed
- **Standalone Operation**: Can be run independently without triggering full review status checks
- **Integration Testing**: Facilitates testing of comment tracking logic in isolation
- **Efficient Processing**: Uses temporary files to handle large comment datasets without command line argument limits

```bash
# Usage: ./update-tracking-efficient.sh <pr-number> <branch-name>
# Example: ./update-tracking-efficient.sh 162 feat/unified-pr-tracker
```

**Features**:
- Merges new comments into the tracking file
- Handles comment deduplication by ID
- Updates last_updated timestamp
- Uses file locking to prevent concurrent access issues
- Efficiently processes large comment files using temporary files

**Note**: The `update-tracking.sh` script is deprecated and should not be used as it can fail with large comment datasets due to command line argument limits.

## Microagent-Driven Workflow (Strict State Machine)

The review cycle is managed by the microagent using a strict state machine that enforces all workflow rules.

### Core Workflow Rules

1. **Only one PR per feature** - The first Google Code Assist review is triggered by opening the PR and marking it "Ready for review"
2. **Polling Logic** - After the first initial push and PR opening, the microagent checks regularly (with configurable polling intervals, defaulting to 120 seconds initial wait then 120 seconds per poll) until a new Google Code Assist review has been posted
3. **Comment Management** - All code review concerns must be addressed in order and kept track of
4. **Review Triggering** - After each round of fixes, the microagent pushes to the initial branch and posts `/gemini review` on the PR. This must only be done once between each Google Code Assist reviews
5. **No Review Spamming** - If a review exists that has unaddressed comments, do not ask for a new review. All Google Code Assist comments must be fixed and the new code pushed before asking again for a new review
6. **Cycle End Conditions** - A code review cycle only ends when:
   - Google Code Assist gets rate limited: "You have reached your daily quota limit. Please wait up to 24 hours and I will start processing your requests again!"
   - Google Code Assist finally reports that nothing is left to be done and the feature is ready to Merge (this has to be determined semantically as part of the workflow by the microagent, not by checking conditions within a script)

### Strict State Machine Workflow

#### State: `InitialReview`
1. **Start**: Agent creates a new PR for the feature
2. **Action**: Agent marks the PR "Ready for review" (this is the *first* trigger)
3. **Action**: Agent calls `check-review-status.sh --wait` to wait for the first set of comments
4. **Transition**: Proceed to `Processing` state based on script output

#### State: `Processing` (Loop)
1. **Read State**: Agent re-reads `pr-review-tracker.json` to get current status
2. **Check Stop Conditions**:
   - If `review_status == "Complete"`: **Stop** - Cycle finished successfully (based on semantic analysis by agent)
   - If `review_status == "RateLimited"` AND no new actionable comments for 24 hours: **Stop** - Cycle finished due to quota limit exhaustion
3. **Check Review Status**:
   - If `review_status == "Commented"`:
     - Read all comments from `pr-review-tracker.json` where `status: "todo"`
     - **If no "todo" comments exist**: This state is invalid. Agent should re-trigger by calling `trigger-review.sh <pr_number>` and go to wait step
     - **If "todo" comments exist**:
       - Address *all* "todo" comments in order
       - Update `pr-review-tracker.json` to mark all addressed comments as `status: "addressed"`
       - Push the new code to the branch
       - Call `trigger-review.sh <pr_number>` *exactly once*
       - Call `check-review-status.sh --wait` to wait for the *next* review
       - Return to start of `Processing` loop
   - If `review_status == "None"` (e.g., if Gemini didn't respond after the wait):
     - Call `trigger-review.sh <pr_number>` to re-trigger
     - Call `check-review-status.sh --wait`
     - Return to start of `Processing` loop
   - If `review_status == "RateLimited"` AND actionable comments exist:
     - Address *all* "todo" comments in order
     - Update `pr-review-tracker.json` to mark all addressed comments as `status: "addressed"`
     - Push the new code to the branch
     - Wait for rate limit to clear (check every 1 minute using `RATE_LIMIT_CHECK_INTERVAL=60`)
     - Call `trigger-review.sh <pr_number>` *exactly once* when rate limit clears
     - Call `check-review-status.sh --wait` to wait for the *next* review
     - Return to start of `Processing` loop

### Implementation Guidelines

- **Polling**: The waiting logic is implemented within the bash scripts themselves (specifically in `check-review-status.sh --wait`)
- **State Validation**: The microagent must validate that all "todo" comments are addressed before triggering a new review
- **Single Trigger**: Only one `/gemini review` comment should be posted between each review cycle
- **Semantic Analysis**: The agent must determine when "nothing is left to be done" based on the content of Google Code Assist's comments

## Usage Examples

### Monitoring Review Status
```bash
# Get the current review status and comment count
./check-review-status.sh feat/new-feature
```

### Triggering a New Review
```bash
# Trigger a new review for PR #123
./trigger-review.sh 123
```

## Configuration

- Use environment variable `GITHUB_TOKEN` for authentication
- Default base branch: `main`
- Tracking file location: `pr-review-tracker.json` in repository root
- Always verify PR creation was successful

## Important Notes

- **This microagent explicitly replaces** the previous `code-review-cycle.md` and `pr-ready-review.md` microagents
- **Follow all SheepVibes testing requirements**: Run backend tests with Redis before creating PRs
- **Update documentation**: Always update CHANGELOG.md and TODO.md upon task completion
- **Polling Logic**: The waiting logic (120s initial wait, then every 120s) is implemented within `check-review-status.sh --wait` script
- **State Enforcement**: The microagent must strictly enforce the state machine workflow to prevent review spamming
- **Comment Tracking**: All comments must be tracked in `pr-review-tracker.json` and addressed before triggering new reviews

## Known Limitations and Workarounds

1. **Automated Trigger**: Use `trigger-review.sh` to automatically post `/gemini review` comments to the PR after pushing changes.
2. **API Rate Limits**: The script implements dedicated rate limit handling with exponential backoff for API requests. Additionally, the polling mechanism (120s initial wait, then every 120s for up to 15 minutes total) is used to wait for asynchronous code review comments while avoiding excessive API calls.
3. **Google Code Assist Rate Limits**: The script now detects Google Code Assist's daily quota limit message and will pause the review cycle when detected.
4. **Concurrent Access**: The script uses file locking to prevent data corruption from simultaneous runs. While it is safe to run multiple instances, it is still recommended to avoid it where possible to prevent contention.
5. **Fallback Strategy**: If Google Code Assist doesn't respond after the configured number of polls, proceed with manual code review.
6. **Error Recovery**: If the tracking file becomes corrupted, delete it and the script will recreate it

## Integration with Existing Workflows

This microagent complements the existing SheepVibes Rules microagent and integrates with:
- Repository testing requirements
- Documentation update procedures
- CI/CD workflows
- Code quality standards
