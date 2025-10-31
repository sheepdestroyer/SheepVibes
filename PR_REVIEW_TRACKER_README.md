
# PR Review Tracker System

A comprehensive system for tracking GitHub PR code reviews with Google Code Assist integration, replacing the previous code-review-cycle and pr-ready-review microagents.

## Overview

This system provides a simplified workflow for managing code reviews that eliminates the need to close and reopen PRs for fresh reviews. Instead, you manually trigger Google Code Assist using the `/gemini review` comment after each push.

## Key Features

1. **Global Tracking File**: `pr-review-tracker.json` maintains state for all working branches
2. **Simplified Workflow**: No more closing/reopening PRs - manually trigger Google Code Assist after each push
3. **Review Status Tracking**: Monitors Google Code Assist status (None, Started, Commented)
4. **Comment Management**: Tracks individual review comments with status (todo, addressed)

### Tools
- **check-review-status.sh**: Enhanced bash script to check Google Code Assist review status
  - Usage: `./check-review-status.sh [branch-name|pr-number] [--wait] [--poll-interval SECONDS]`
  - Returns: None, Started, or Commented
  - With `--wait`: Polls for comments and saves them to `comments_<PR#>.json`
  - **Note**: To trigger reviews, manually comment `/gemini review` in the PR after pushing changes

## Migration from Previous System

The old workflow that required closing and reopening PRs for fresh reviews has been replaced with a simpler approach:

**Before (old system):**
1. Create PR
2. Wait for reviews
3. Address comments
4. Close PR
5. Open new PR (repeat)

**After (new system):**
1. Create PR
2. Wait for reviews
3. Address comments
4. Push changes
5. Manually trigger Google Code Assist using `/gemini review` comment (repeat)

## Usage

### For New Branches
```bash
# Create branch and make changes
git checkout -b feat/new-feature
# ... make changes and commit
git push origin feat/new-feature

# Create PR (always mark ready to review)
# Comment /gemini review in the PR

# Check review status
./check-review-status.sh feat/new-feature --wait
```

### For Existing Branches
```bash
# Address comments, then push and manually trigger re-review
git add .
git commit -m "Address review comments"
git push origin feat/new-feature
# Manually trigger Google Code Assist by commenting `/gemini review` in the PR
```

### Tracking File Structure
The `pr-review-tracker.json` file maintains:
- Branch information
- PR numbers
- Review status (None, Started, Commented)
- Comment tracking with status (todo, addressed)
- Last updated timestamps

## Script Options

### Basic Usage
```bash
./check-review-status.sh feat/my-branch
./check-review-status.sh 123
```

### Advanced Usage
```bash
# Wait for comments (polls every 60s for up to 1 hour)
./check-review-status.sh feat/my-branch --wait

# Wait with custom polling interval
./check-review-status.sh feat/my-branch --wait --poll-interval 30

# Check by PR number
./check-review-status.sh 123 --wait
```

## Integration with SheepVibes

This system integrates with existing SheepVibes workflows:
- Follow all testing requirements (run backend tests with Redis)
- Update documentation files (CHANGELOG.md, TODO.md)
- Follow repository guidelines and CI/CD processes

## Known Limitations

1. **Manual Trigger Required**: You must manually comment `/gemini review` in the PR
2. **API Rate Limits**: Script implements rate limit handling with exponential backoff
3. **Concurrent Access**: File locking prevents conflicts but avoid simultaneous operations
4. **Fallback Strategy**: If no comments after 1 hour, proceed with manual review

## Error Recovery

- If tracking file becomes corrupted: Delete it and the script will recreate
- If API rate limits hit: Script waits for reset time automatically
- If branch has no PR: Script reports "None" status

## Files

- `.openhands/microagents/pr-review-tracker.md` - Main microagent documentation
- `check-review-status.sh` - Enhanced review status checking script
- `pr-review-tracker.json` - Global tracking file
- `PR_REVIEW_TRACKER_README.md` - This documentation file

