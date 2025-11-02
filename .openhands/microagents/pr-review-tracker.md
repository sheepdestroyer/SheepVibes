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

Track and manage GitHub PR code reviews through a simplified workflow that eliminates the need to close/reopen PRs for fresh reviews. Instead, manually trigger Google Code Assist using `/gemini review` comment after each push.

## Core Principles

1. **Global Tracking**: Maintain a dedicated global file (`pr-review-tracker.json`) with sections for each working branch
2. **Review Status Tracking**: Track Google Code Assist review status (None, Started, Commented) for each PR
3. **Comment Management**: Track individual review comments with status (todo, addressed)
4. **Manual Trigger**: Manually trigger Google Code Assist using `/gemini review` comment after each push instead of closing/reopening PRs
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

- **None**: No Google Code Assist activity detected
- **Started**: Google Code Assist has started review but no comments yet
- **Commented**: Comments have been provided and need addressing

## Tools and Scripts

### check-review-status.sh

This script checks the current Google Code Assist review status for a branch or PR and returns a JSON object with the status and comment count.

```bash
# Usage: ./check-review-status.sh [branch-name|pr-number] [--wait]
```

**Features**:
- Checks Google Code Assist review status (`None`, `Started`, `Commented`)
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
- `0`: Success with review status output
- `1`: Error occurred
- `2`: No open PR found for branch

**Note**: To trigger a new Google Code Assist review, you must manually comment `/gemini review` in the GitHub PR interface after pushing changes.

## Error Handling

- **Authentication issues**: Update remote URL with current GITHUB_TOKEN
- **Branch conflicts**: Create new unique branch names
- **No comments received**: After waiting the maximum poll time (5 polls, up to 5 minutes total), proceed with manual code review
- **API rate limits**: Script implements automatic rate limit handling with exponential backoff

### trigger-review.sh

This script triggers a new Google Code Assist review by posting a `/gemini review` comment to the specified PR.

```bash
# Usage: ./trigger-review.sh [pr-number]
```

## Microagent-Driven Workflow

The review cycle is managed by the microagent, which uses the scripts to interact with GitHub.

1.  **PR Creation**: The microagent creates a PR and triggers an initial review using `trigger-review.sh`.
2.  **Review Monitoring**: The microagent uses `check-review-status.sh` to monitor the review status.
3.  **Comment Analysis**: When comments are received, the microagent analyzes them to determine if they are actionable.
4.  **Addressing Feedback**: If the comments are actionable, the microagent addresses the feedback and pushes the changes.
5.  **Re-triggering Review**: After pushing changes, the microagent triggers a new review using `trigger-review.sh`.
6.  **Cycle End**: The cycle ends when the microagent determines that there are no more actionable comments. This can be because Google Code Assist reports no issues, or because the microagent has addressed all comments.

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

- This microagent replaces the previous code-review-cycle and pr-ready-review microagents
- **Follow all SheepVibes testing requirements**: Run backend tests with Redis before creating PRs
- **Update documentation**: Always update CHANGELOG.md and TODO.md upon task completion
- The simplified workflow eliminates the need to close/reopen PRs for fresh reviews
- Manual triggering of Google Code Assist using `/gemini review` comment after each push is more efficient

## Known Limitations and Workarounds

1. **Automated Trigger**: Use `trigger-review.sh` to automatically post `/gemini review` comments to the PR after pushing changes.
2. **API Rate Limits**: The script implements polling with increasing intervals (60 seconds to 300 seconds) to avoid hitting GitHub API limits.
3. **Concurrent Access**: The script uses file locking to prevent data corruption from simultaneous runs. While it is safe to run multiple instances, it is still recommended to avoid it where possible to prevent contention.
4. **Fallback Strategy**: If Google Code Assist doesn't respond after 5 polls (total wait time: 15 minutes), proceed with manual code review.
5. **Error Recovery**: If the tracking file becomes corrupted, delete it and the script will recreate it

## Integration with Existing Workflows

This microagent complements the existing SheepVibes Rules microagent and integrates with:
- Repository testing requirements
- Documentation update procedures
- CI/CD workflows
- Code quality standards
