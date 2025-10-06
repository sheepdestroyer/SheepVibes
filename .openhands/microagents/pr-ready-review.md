---
name: PR Ready to Review
type: knowledge
version: 1.0.0
agent: CodeActAgent
triggers: []
---

# PR Ready to Review Microagent

This microagent provides guidance for ensuring that pull requests are immediately marked as "ready to review" after opening them.

## Purpose

Ensure that all pull requests created in the SheepVibes repository are immediately marked as ready for review, rather than being left as draft PRs.

## Core Rules

1. **Always mark PRs as ready to review** immediately after opening them
2. **Never leave PRs in draft state** unless explicitly requested by the user
3. **Apply appropriate labels** when creating PRs
4. **Follow repository templates** if they exist

## Workflow

### When Creating a Pull Request:
1. Set `draft: false` when using the `create_pr` function
2. Include clear, descriptive titles and descriptions
3. Reference any related issues or context
4. Ensure all required checks pass before marking as ready

## Implementation Guidelines

- Use the GitHub API directly via `create_pr` function
- Set appropriate labels based on the changes (e.g., "enhancement", "bug", "documentation")
5. Update relevant documentation files (CHANGELOG.md, TODO.md) as needed

## Error Handling

- If authentication fails, update remote URL with current GITHUB_TOKEN
- If branch conflicts occur, create a new unique branch name
- Always verify the PR was created successfully

## Usage Examples

When creating a PR for a new feature:
- Title: "feat: Add new widget functionality"
- Labels: "enhancement"
- Description: Include purpose, changes made, and testing results

## Important Notes

- This microagent focuses on the PR creation process specifically
- It complements the existing SheepVibes Rules microagent
- Follow all existing repository rules and testing requirements

## Configuration

- Use environment variable `GITHUB_TOKEN` for authentication
- Default base branch: `main`
- Always create meaningful branch names that describe the changes