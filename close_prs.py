#!/usr/bin/env python3
"""Check status of PRs and optionally close them."""
import json
import os
import subprocess
import sys

TOKEN = os.environ.get("GITHUB_MCP_PAT", "")
REPO = "sheepdestroyer/SheepVibes"
BASE = f"https://api.github.com/repos/{REPO}"

# All PRs to close
PRS_TO_CLOSE = [
    # bulk_cache_invalidation (keep 447)
    446, 436, 433, 432, 426, 425, 422, 418, 416, 413, 410,
    # feed_orm_bypass (keep 443)
    441, 435,
    # datetime_serialization (keep 442)
    438, 408, 406, 403, 402, 399,
    # opml_validation (keep 440)
    439, 424, 405,
    # url_validation (keep 428)
    420, 401,
    # xss_innerhtml (keep 423)
    417, 400,
    # frontend_dom_cache (keep 415)
    414, 412,
    # opml_url_query (keep 427)
    419, 411, 409, 407, 404, 398,
]

def api_get(path):
    """GET from GitHub API."""
    cmd = [
        "curl", "-s",
        "-H", f"Authorization: token {TOKEN}",
        "-H", "Accept: application/vnd.github.v3+json",
        f"{BASE}{path}"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return {"error": r.stderr}
    return json.loads(r.stdout)

def api_patch(path, body):
    """PATCH to GitHub API."""
    cmd = [
        "curl", "-s", "-X", "PATCH",
        "-H", f"Authorization: token {TOKEN}",
        "-H", "Accept: application/vnd.github.v3+json",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(body),
        f"{BASE}{path}"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return {"error": r.stderr}
    return json.loads(r.stdout)

def api_delete(path):
    """DELETE from GitHub API."""
    cmd = [
        "curl", "-s", "-X", "DELETE",
        "-H", f"Authorization: token {TOKEN}",
        "-H", "Accept: application/vnd.github.v3+json",
        f"{BASE}{path}"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.returncode == 0, r.stdout

def check_status():
    """Check all PR statuses."""
    print(f"{'PR':>5} | {'State':<8} | Title")
    print("-" * 70)
    for pr in PRS_TO_CLOSE:
        data = api_get(f"/pulls/{pr}")
        if "error" in data:
            print(f"PR#{pr:>3} | ERROR   | {data['error'][:50]}")
            continue
        state = data.get("state", "?")
        title = data.get("title", "?")
        print(f"PR#{pr:>3} | {state:<8} | {title}")

def close_prs(dry_run=False):
    """Close all open PRs and delete their branches."""
    results = {
        "already_closed": [],
        "closed": [],
        "failed": [],
        "branch_deleted": [],
        "branch_failed": [],
    }
    
    for pr in PRS_TO_CLOSE:
        data = api_get(f"/pulls/{pr}")
        if "error" in data:
            print(f"PR#{pr}: ERROR fetching - {data['error'][:80]}")
            results["failed"].append(pr)
            continue
        
        state = data.get("state", "?")
        title = data.get("title", "?")
        head_ref = data.get("head", {}).get("ref", "?")
        
        if state == "closed":
            print(f"PR#{pr}: Already closed - {title}")
            results["already_closed"].append(pr)
            # Still try to delete branch
            if not dry_run:
                ok, _ = api_delete(f"/git/refs/heads/{head_ref}")
                if ok:
                    print(f"  -> Deleted branch '{head_ref}'")
                    results["branch_deleted"].append(pr)
                else:
                    print(f"  -> Branch '{head_ref}' delete failed or already gone")
                    results["branch_failed"].append(pr)
            continue
        
        if dry_run:
            print(f"PR#{pr}: [DRY RUN] Would close - {title}")
            results["closed"].append(pr)
            continue
        
        # Close the PR
        close_data = api_patch(f"/pulls/{pr}", {"state": "closed"})
        if "error" in close_data:
            print(f"PR#{pr}: FAILED to close - {close_data['error'][:80]}")
            results["failed"].append(pr)
            continue
        
        print(f"PR#{pr}: Closed - {title}")
        results["closed"].append(pr)
        
        # Delete the branch
        ok, _ = api_delete(f"/git/refs/heads/{head_ref}")
        if ok:
            print(f"  -> Deleted branch '{head_ref}'")
            results["branch_deleted"].append(pr)
        else:
            print(f"  -> Branch '{head_ref}' delete failed or already gone")
            results["branch_failed"].append(pr)
    
    print("\n" + "=" * 50)
    print("RESULTS:")
    print(f"  Already closed: {len(results['already_closed'])} {results['already_closed']}")
    print(f"  Newly closed:   {len(results['closed'])} {results['closed']}")
    print(f"  Failed:         {len(results['failed'])} {results['failed']}")
    print(f"  Branch deleted: {len(results['branch_deleted'])}")
    print(f"  Branch failed:  {len(results['branch_failed'])} {results['branch_failed']}")
    
    return results

if __name__ == "__main__":
    if not TOKEN:
        print("ERROR: GITHUB_MCP_PAT not set", file=sys.stderr)
        sys.exit(1)
    
    mode = len(sys.argv) > 1 and sys.argv[1] in ("close", "check", "dry-run") and sys.argv[1] or "check"
    
    if mode == "check":
        check_status()
    elif mode == "dry-run":
        close_prs(dry_run=True)
    elif mode == "close":
        close_prs(dry_run=False)
    else:
        print(f"Usage: {sys.argv[0]} [check|dry-run|close]")
        sys.exit(1)
