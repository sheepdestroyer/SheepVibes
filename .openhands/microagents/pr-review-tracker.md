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

This bash script checks the current Google Code Assist review status for a branch or PR and can wait for comments to be available:

```bash
#!/bin/bash
# Usage: ./check-review-status.sh [branch-name|pr-number] [--wait] [--poll-interval SECONDS]

# Examples:
#   ./check-review-status.sh feat/new-widget
#   ./check-review-status.sh 123 --wait
#   ./check-review-status.sh feat/new-widget --wait --poll-interval 120
```

**Features**:
- Checks Google Code Assist review status (None, Started, Commented)
- With `--wait` flag: Polls for comments until available, starting at 30 seconds and increasing up to 5 minutes (max 10 polls)
- Extracts and saves Google Code Assist comments to `comments_<PR#>.json`
- Updates the global tracking file automatically

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

This bash script posts a `/gemini review` comment to a PR to trigger a new review:

```bash
#!/bin/bash
# Usage: ./trigger-review.sh [pr-number]

# Example:
#   ./trigger-review.sh 123
```

## Workflow

1.  **Branch Setup**: Create a new branch with a meaningful name.

2.  **PR Creation**: Create a PR and mark it as ready for review. Push your changes and trigger an initial review with `./trigger-review.sh [pr-number]`

3.  **Review Cycle**:
    - Use `check-review-status.sh` to monitor the review status.
    - When comments are received, they are added to the `pr-review-tracker.json` file with a "todo" status.
    - Address all "todo" comments and update their status to "addressed" in the tracking file.
    - Push your changes and trigger a new review with `./trigger-review.sh [pr-number]`.

4.  **Cycle End**: The review cycle ends when `check-review-status.sh` returns "None" status, which means that Google Code Assist has no remaining issues.

5.  **Completion**: When all comments are addressed and the PR is approved, merge the PR.
## Usage Examples

### Creating a New Feature Branch
```bash
git checkout -b feat/new-feature
# Make changes, add tests
git add .
git commit -m "feat: Add new feature"
git push origin feat/new-feature
# Create PR and mark ready to review
# Comment /gemini review in PR
```

### Monitoring Review Status
```bash
# Check current status
./check-review-status.sh feat/new-feature

# Wait for comments
./check-review-status.sh feat/new-feature --wait

# Wait with custom polling interval
./check-review-status.sh feat/new-feature --wait --poll-interval 120
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
2. **API Rate Limits**: The script implements polling with increasing intervals (30 seconds to 5 minutes) to avoid hitting GitHub API limits.
3. **Concurrent Access**: The script uses file locking to prevent data corruption from simultaneous runs. While it is safe to run multiple instances, it is still recommended to avoid it where possible to prevent contention.
4. **Fallback Strategy**: If Google Code Assist doesn't respond after 10 polls (max 5 minutes), proceed with manual code review.
5. **Error Recovery**: If the tracking file becomes corrupted, delete it and the script will recreate it

## Integration with Existing Workflows

This microagent complements the existing SheepVibes Rules microagent and integrates with:
- Repository testing requirements
- Documentation update procedures
- CI/CD workflows
- Code quality standards
