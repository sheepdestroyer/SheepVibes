
# PR Review Tracker System

This system replaces the previous `code-review-cycle.md` and `pr-ready-review.md` microagents with a unified approach for tracking GitHub PR code reviews.

## What's New

### Combined Microagent
- **File**: `.openhands/microagents/pr-review-tracker.md`
- **Purpose**: Tracks GitHub PR code reviews with simplified workflow
- **Triggers**: `review-cycle`, `pr-review`, `code-review`

### Key Features
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
# Create branch and work on changes
git checkout -b feat/new-feature

# Create PR (automatically marked ready to review)
# Use create_pr function with draft: false

# Check review status
./check-review-status.sh feat/new-feature

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
- Review status
- Individual comments with status
- Last updated timestamps

## Benefits
- **Simpler workflow**: No PR closing/reopening
- **Better tracking**: Centralized state management
- **Manual control**: Explicit triggering of Google Code Assist
- **Continuous improvement**: Iterative review cycles without disruption

