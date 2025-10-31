---
name: PR Review Tracker
type: knowledge
version: 1.0.0
agent: CodeActAgent
triggers: [review-cycle, pr-review, code-review]
---

# PR Review Tracker Microagent

This microagent provides a comprehensive system for tracking and managing GitHub PR code reviews, combining the functionality of the previous code-review-cycle and pr-ready-review microagents with a simplified workflow.

## Purpose

Track and manage GitHub PR code reviews through a systematic approach that:
- Maintains a global tracking file for all working branches
- Monitors Google Code Assist review status
- Simplifies the review cycle by manually triggering reviews after each push
- Eliminates the need to close and reopen PRs for fresh reviews

## Core Rules

1. **Global Tracking**: Maintain a dedicated global file (`pr-review-tracker.json`) with sections for each working branch
2. **Review Status Tracking**: Track Google Code Assist review status (None, Started, Commented) for each PR
3. **Comment Management**: Track individual review comments with status (todo, addressed)
4. **Manual Trigger**: Manually trigger Google Code Assist using `/gemini review` comment after each push instead of closing/reopening PRs
5. **Ready to Review**: Always mark PRs as ready to review immediately after creation

## Global Tracking File Structure

The microagent maintains `pr-review-tracker.json` with the following structure:

```json
{
  "branches": {
    "branch-name": {
      "description": "Short description of changes",
      "pr_number": 123,
      "review_status": "None|Started|Commented",
      "comments": [
        {
          "comment_id": 456,
          "status": "todo|addressed",
          "content": "Comment text",
          "file": "path/to/file.py",
          "line": 42
        }
      ],
      "last_updated": "2024-01-15T10:30:00Z"
    }
  },
  "last_updated": "2024-01-15T10:30:00Z"
}
```

## Workflow

### For Each New Branch:

1. **Branch Setup**:
   - Create a new branch with meaningful name
   - Add entry to global tracking file with branch name and description
   - Set initial review status to "None"

2. **PR Creation**:
   - Create PR with clear title and description
   - Set `draft: false` to mark as ready to review
   - Update tracking file with PR number
   - Push changes to trigger initial review

3. **Review Cycle**:
   - Use `check-review-status.sh` to monitor Google Code Assist status
   - Update tracking file with current review status
   - When comments are received, add them to tracking file with "todo" status
   - Address all "todo" comments
   - Update comment status to "addressed" when fixed
   - Push changes and manually trigger Google Code Assist using `/gemini review` comment for re-review

4. **Completion**:
   - When all comments are addressed and PR is approved
   - Merge the PR
   - Archive the branch entry in tracking file

## Implementation Guidelines

### When Creating Pull Requests:
1. Use `create_pr` function with `draft: false`
2. Include meaningful branch names that describe changes
3. Apply appropriate labels (enhancement, bug, documentation)
4. Update tracking file immediately after PR creation

### When Addressing Comments:
1. Read all comments from GitHub API
2. Update tracking file with new comments as "todo"
3. Implement requested changes systematically
4. Update comment status to "addressed" after fixes
5. Verify tests pass after changes
6. Update documentation (CHANGELOG.md, TODO.md) as needed

### Review Status Management:
- **None**: No review activity detected
- **Started**: Review in progress but no comments yet
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
- **API rate limits**: Implement retry logic with exponential backoff
- **Missing tracking file**: Create initial structure automatically

## Usage Examples

### Example Workflow:
1. Create branch: `feat/new-widget-functionality`
2. Update tracking: Add branch entry with description
3. Create PR: "feat: Add new widget functionality"
4. Check status: `./check-review-status.sh feat/new-widget-functionality`
5. Address comments: Update tracking file as comments are addressed
6. Push changes and manually trigger re-review

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
- Documentation updates (CHANGELOG.md, TODO.md)
- CI/CD workflows
- Code quality standards
