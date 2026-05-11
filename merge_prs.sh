#!/bin/bash
# Script to merge PRs by resolving conflicts with main
# Usage: ./merge_prs.sh PR_NUMBER

set -e
cd /home/sheepdestroyer/LAB/SheepVibes

PR_NUM=$1
REPO="sheepdestroyer/SheepVibes"

echo "=== Processing PR #$PR_NUM ==="

# Get PR info
PR_BRANCH=$(gh pr view $PR_NUM --json headRefName --jq '.headRefName')
PR_TITLE=$(gh pr view $PR_NUM --json title --jq '.title')
echo "Branch: $PR_BRANCH"
echo "Title: $PR_TITLE"

# Fetch the branch
git fetch origin $PR_BRANCH 2>/dev/null

# Create a local merge branch
MERGE_BRANCH="pr${PR_NUM}-merged-$(date +%s)"
git checkout -b $MERGE_BRANCH origin/$PR_BRANCH 2>/dev/null

# Merge main into it
git merge origin/main --no-ff -m "Merge main into PR #$PR_NUM" 2>/dev/null || true

# Resolve conflicts - accept main for docs files, keep PR for code files
if git diff --name-only --diff-filter=U 2>/dev/null | grep -q .; then
    echo "Resolving conflicts..."
    # For .jules/ files (docs), accept main (theirs)
    git checkout --theirs .jules/bolt.md 2>/dev/null || true
    git checkout --theirs .jules/sentinel.md 2>/dev/null || true
    # For everything else, keep PR (ours)
    for f in $(git diff --name-only --diff-filter=U 2>/dev/null | grep -v "^\.jules/"); do
        git checkout --ours "$f" 2>/dev/null || true
    done
    git add -A
    git commit -m "Resolve merge conflicts for PR #$PR_NUM" 2>/dev/null || true
fi

# Push to new branch
git push origin $MERGE_BRANCH 2>/dev/null

# Close old PR
gh pr close $PR_NUM 2>/dev/null

# Create new PR
NEW_PR=$(gh pr create --head $MERGE_BRANCH --base main --title "$PR_TITLE" --body "Rebased version of closed PR #$PR_NUM. Conflicts resolved." 2>/dev/null)
NEW_PR_NUM=$(echo $NEW_PR | grep -oP '#\K\d+')
echo "New PR: $NEW_PR_NUM"

# Wait for checks and merge
sleep 5
MERGE_STATE=$(gh pr view $NEW_PR_NUM --json mergeStateStatus --jq '.mergeStateStatus')
echo "Merge state: $MERGE_STATE"

if [[ "$MERGE_STATE" == "MERGEABLE" || "$MERGE_STATE" == "UNSTABLE" || "$MERGE_STATE" == "CLEAN" || "$MERGE_STATE" == "BEHIND" ]]; then
    gh pr merge $NEW_PR_NUM --squash --delete-branch 2>/dev/null && echo "Merged PR #$NEW_PR_NUM" || echo "Failed to merge PR #$NEW_PR_NUM"
else
    echo "PR #$NEW_PR_NUM not mergeable (state: $MERGE_STATE)"
fi

# Cleanup
git checkout main 2>/dev/null
git branch -D $MERGE_BRANCH 2>/dev/null || true

echo "=== Done with PR #$PR_NUM ==="
