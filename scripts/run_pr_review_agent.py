#!/usr/bin/env python3
import argparse
import os
import sys
import asyncio

# Ensure openhands is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openhands.microagents.workflows.pr_review import PRReviewWorkflow

async def main():
    parser = argparse.ArgumentParser(description="Run OpenHands PR Review Agent")
    parser.add_argument("pr_number", type=int, help="PR Number")
    parser.add_argument("--repo", help="Repository (owner/name). Defaults to origin remote.")
    parser.add_argument("--token", help="GitHub Token. Defaults to GITHUB_TOKEN env var.")
    parser.add_argument("--max-cycles", type=int, default=50, help="Maximum cycles to run.")
    parser.add_argument("--interval", type=int, default=120, help="Interval in seconds between checks.")

    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN not set.")
        sys.exit(1)

    repo = args.repo
    if not repo:
        # Try to detect repo from git config
        try:
            import git
            r = git.Repo('.')
            url = r.remotes.origin.url
            # Parse owner/name from url
            # git@github.com:owner/name.git or https://github.com/owner/name.git
            if "github.com" in url:
                parts = url.split("github.com")[-1].strip("/").replace(".git", "").split("/")
                repo = f"{parts[-2]}/{parts[-1]}"
        except Exception as e:
            print(f"Error detecting repo: {e}")

    if not repo:
        print("Error: Repository not provided and could not be detected.")
        sys.exit(1)

    print(f"Running agent for {repo} PR #{args.pr_number}")

    workflow = PRReviewWorkflow(repo, args.pr_number, token)
    await workflow.run_autonomous_loop(max_cycles=args.max_cycles, interval_seconds=args.interval)

if __name__ == "__main__":
    asyncio.run(main())
