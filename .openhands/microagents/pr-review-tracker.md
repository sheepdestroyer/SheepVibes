---
name: PR Review Tracker
type: keyword-triggered
version: 1.0
agent: CodeActAgent
triggers:
- review-cycle
- pr-review
- code-review
- google-code-assist
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
#   ./check-review-status.sh feat/new-widget --wait --poll-interval 30
```

**Features**:
- Checks Google Code Assist review status (None, Started, Commented)
- With `--wait` flag: Polls for comments until available (up to 1 hour)
- Extracts and saves Google Code Assist comments to `comments_<PR#>.json`
- Updates the global tracking file automatically

**Note**: To trigger a new Google Code Assist review, you must manually comment `/gemini review` in the GitHub PR interface after pushing changes.

## Error Handling

- **Authentication issues**: Update remote URL with current GITHUB_TOKEN
- **Branch conflicts**: Create new unique branch names
- **No comments received**: After waiting the maximum poll time (1 hour), proceed with manual code review
- **API rate limits**: Script implements automatic rate limit handling with exponential backoff

## Workflow

### 1. Branch Setup
   - Create a new branch with meaningful name
   - Add branch entry to tracking file with initial state

### 2. PR Creation
   - Create PR with `draft: false` (always ready to review)
   - Include clear title and description
   - Update tracking file with PR number
   - Push changes and manually trigger an initial review with a `/gemini review` comment

### 3. Review Cycle
   - Use `check-review-status.sh` to monitor Google Code Assist status
   - Update tracking file with current review status
   - When comments are received, add them to tracking file with "todo" status
   - Address all "todo" comments
   - Update comment status to "addressed" when fixed
   - Push changes and manually trigger Google Code Assist using `/gemini review` comment for re-review

### 4. Completion
   - When all comments are addressed and PR is approved
   - Merge the PR

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
./check-review-status.sh feat/new-feature --wait --poll-interval 30
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

1. **Manual Trigger Required**: You must manually comment `/gemini review` in the PR after pushing changes
2. **API Rate Limits**: The script implements polling with 60-second intervals to avoid hitting GitHub API limits
3. **Concurrent Access**: Avoid running multiple instances of the script on the same branch simultaneously
4. **Fallback Strategy**: If Google Code Assist doesn't respond within 1 hour, proceed with manual code review
5. **Error Recovery**: If the tracking file becomes corrupted, delete it and the script will recreate it

## Integration with Existing Workflows

This microagent complements the existing SheepVibes Rules microagent and integrates with:
- Repository testing requirements
- Documentation update procedures
- CI/CD workflows
- Code quality standards
