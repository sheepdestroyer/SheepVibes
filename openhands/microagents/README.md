# OpenHands Microagents

This directory contains the OpenHands microagent system.

## Autonomous PR Review Agent

This agent autonomously reviews Pull Requests using Google Code Assist (Gemini), addresses feedback by applying code fixes, and loops until the PR is approved.

### Usage

To run the autonomous agent for a specific PR:

```bash
export GITHUB_TOKEN=your_token
python scripts/run_pr_review_agent.py <pr_number> --repo owner/repo
```

### Features

- Triggers Google Code Assist review (`/gemini review`).
- Polls for comments and status updates.
- Detects "LGTM" to complete the workflow.
- Detects "Rate Limit" and waits.
- Parses diff blocks from comments and applies them to the code.
- Commits and pushes fixes automatically.
