# Code Review Cycle: Keeping and Amending PR Descriptions

This guide provides best practices for maintaining and updating pull request descriptions during iterative code review cycles.

## Purpose

When going through multiple review cycles, it's crucial to maintain continuity in PR descriptions while incorporating new information and changes. This ensures reviewers have proper context and can track the evolution of the changes.

## Core Principles

### 1. Preserve Historical Context
- Keep the original PR description as a foundation
- Maintain links to previous discussions and decisions
- Document the evolution of the solution

### 2. Incremental Updates
- Add new sections for each review cycle
- Clearly mark what has changed since the last review
- Update status and progress indicators

### 3. Clear Communication
- Explain how feedback was addressed
- Highlight remaining open questions
- Provide context for new reviewers

## Template Structure for Multi-Cycle PRs

```markdown
# [Feature/Bug]: [Brief Description]

## Original Description
[Copy of the initial PR description]

## Current Status
- **Cycle**: [Current cycle number]
- **Previous PR**: [Link to closed PR]
- **Last Review**: [Date of last review]

## Changes Since Last Review
### Addressed Feedback
- [ ] [Brief description of change 1] - [Link to comment]
- [ ] [Brief description of change 2] - [Link to comment]

### New Changes
- [Description of any additional changes made]

## Remaining Questions / Open Issues
- [Question 1 for reviewers]
- [Question 2 for reviewers]

## Testing
- [Updated testing information]
- [New test results]

## Review Checklist
- [ ] All previous feedback addressed
- [ ] Tests updated and passing
- [ ] Documentation updated
- [ ] Code follows project conventions
```

## Workflow for Each Review Cycle

### Before Closing Current PR
1. **Document Changes**: Add a "Changes Since Last Review" section
2. **Update Status**: Modify the current status section
3. **Capture Context**: Save important discussion points
4. **Prepare Template**: Copy the updated description for the next PR

### When Opening New PR
1. **Use Updated Template**: Start with the description from the previous PR
2. **Increment Cycle Number**: Update the cycle counter
3. **Add Previous PR Link**: Include link to the closed PR
4. **Clear Completed Items**: Remove checkboxes for addressed feedback
5. **Add New Sections**: Include any new changes or questions

## Best Practices

### Description Maintenance
- **Keep it concise**: Remove outdated information while preserving context
- **Use checklists**: Make it easy to track what's been addressed
- **Link to comments**: Provide direct links to GitHub comments for context
- **Version the description**: Consider keeping a changelog of description updates

### Communication
- **Be transparent**: Clearly state what changed and why
- **Acknowledge feedback**: Show that reviewer input was valued and implemented
- **Ask specific questions**: Guide reviewers to focus on new areas
- **Provide context**: Help new reviewers understand the history

## Example Evolution

### Cycle 1 Description
```markdown
# feat: Add infinite scrolling to feed items

## Problem
Users currently need to click "Load More" to see additional feed items. This creates a poor user experience.

## Solution
Implement infinite scrolling using Intersection Observer API.

## Testing
- Manual testing in Chrome, Firefox, Safari
- Unit tests for scroll detection
```

### Cycle 2 Description (After Review)
```markdown
# feat: Add infinite scrolling to feed items

## Original Description
[Previous description...]

## Current Status
- **Cycle**: 2
- **Previous PR**: #123 (closed)
- **Last Review**: 2024-01-15

## Changes Since Last Review
### Addressed Feedback
- [x] Added error handling for network failures - [#123-comment-1]
- [x] Implemented loading state indicators - [#123-comment-2]
- [x] Added throttle to scroll events - [#123-comment-3]

### New Changes
- Added accessibility attributes for screen readers
- Improved mobile touch responsiveness

## Remaining Questions
- Should we add a "Back to Top" button for long feeds?
- Is the loading indicator clear enough for users?

## Testing
- Updated unit tests for error states
- Manual testing on mobile devices
- Accessibility testing with screen readers
```

## Tools and Automation

### GitHub Actions
Consider creating workflows that:
- Automatically add cycle numbers to PR titles
- Copy descriptions from previous PRs
- Update status sections

### Templates
Create PR templates in `.github/PULL_REQUEST_TEMPLATE/` that include:
- Cycle tracking sections
- Change log placeholders
- Review checklist templates

## Common Pitfalls to Avoid

1. **Losing context**: Don't start fresh with each PR - maintain the history
2. **Information overload**: Remove resolved items to keep the description focused
3. **Missing links**: Always include references to previous discussions
4. **Inconsistent formatting**: Use consistent section headers and structure

## Success Metrics

A successful multi-cycle PR description should:
- Help reviewers quickly understand what's new
- Provide context for the changes
- Show progress and responsiveness to feedback
- Make it easy to track the evolution of the solution

---

*This document is part of the SheepVibes development guidelines. Update as needed based on team feedback and evolving best practices.*
