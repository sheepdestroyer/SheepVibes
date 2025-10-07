---
name: Code Review Cycle
type: knowledge
version: 1.0.0
agent: CodeActAgent
triggers: [review-cycle]
---

# Code Review Cycle Microagent

This microagent provides guidance for iteratively addressing code reviews through a systematic cycle of review, fix, and re-review.

## Purpose

Automate the process of addressing code review comments by creating a cycle that:
1. Checks latest PR and Looks for code reviews from Google Code Assist and other agents
2. Addresses all review comments
3. Closes the current PR
4. Opens a new PR to trigger fresh reviews and Waits 5 minutes for new code reviews.

## Core Rules

1. **Wait for reviews**: After creating a PR and marking it ready to review, wait 5 minutes for Google Code Assist and other agents to provide feedback
2. **Retry if no comments**: If no comments are received after 5 minutes, wait 5 more minutes and try one last time
3. **Address all comments**: Thoroughly review and implement all feedback from code reviews
4. **Close and reopen**: Close the current PR and open a new one to trigger fresh reviews
5. **Maximum 10 cycles**: Repeat the cycle for a maximum of 10 iterations

## Workflow

### Initial Setup:
1. Create a new branch with a meaningful name that describes the changes
2. Ensure the branch name is unique to avoid conflicts

### Code Review Cycle (Repeat up to 10 times):
1. **Create PR**: Open a pull request with clear title and description
2. **Mark ready**: Immediately mark the PR as ready to review (not draft)
3. **Wait for reviews**: 
   - Wait 5 minutes for Google Code Assist and other agents to provide feedback
   - If no comments received, wait 5 more minutes and check one last time
4. **Review comments**: Read and analyze all code review comments
5. **Address feedback**: Implement all requested changes and fixes
6. **Commit changes**: Commit the fixes to the local branch
7. **Close PR**: Close the current pull request
8. **Push changes**: Push the latest changes to the branch
9. **Open new PR**: Create a new pull request to trigger fresh reviews
10. **Back to step 2**: Iterate


## Implementation Guidelines

### When Creating Pull Requests:
1. Use `create_pr` function with `draft: false`
2. Create meaningful branch names that describe the changes
3. Follow repository templates if they exist
4. Apply appropriate labels (e.g., "enhancement", "bug", "documentation")
5. Include clear descriptions of changes made and purpose

### When Addressing Comments:
1. Read all comments thoroughly
2. Implement all requested changes
3. Verify tests pass after changes
4. Update documentation (CHANGELOG.md, TODO.md) as needed

## Error Handling

- **Authentication issues**: Update remote URL with current GITHUB_TOKEN
- **Branch conflicts**: Create new unique branch names
- **No comments received**: After waiting 10 minutes total, proceed to close and reopen
- **Maximum cycles reached**: Stop after 10 iterations and report completion

## Usage Examples

### Example Cycle:
1. Create branch: `feat/code-review-cycle-agent`
2. Open PR: "feat: Add code review cycle microagent"
3. Wait 5 minutes for reviews
4. If comments received, address them
5. Close current PR
6. Push changes
7. Open new PR with updated description

## Configuration

- Use environment variable `GITHUB_TOKEN` for authentication
- Default base branch: `main`
- Always verify PR creation was successful

## Important Notes

- This microagent complements the existing PR Ready to Review and SheepVibes Rules microagents
- Follow all repository testing requirements and validation workflows, including running the full test suite before each PR creation.
- Update relevant documentation files upon completion of each cycle
