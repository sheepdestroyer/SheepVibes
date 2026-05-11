#!/usr/bin/env python3
"""Find and close Jules sessions in AWAITING_USER_FEEDBACK for SheepVibes repo."""
import json
import os
import subprocess
import sys

TOKEN = os.environ.get("JULES_API_KEY", "")
BASE = "https://jules.googleapis.com/v1alpha"
REPO_SOURCE = "sources/github/sheepdestroyer/SheepVibes"

def api_get(path):
    """GET from Jules API."""
    cmd = [
        "curl", "-s",
        "-H", f"x-goog-api-key: {TOKEN}",
        f"{BASE}{path}"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return {"error": r.stderr}
    return json.loads(r.stdout)

def api_post(path, body=None):
    """POST to Jules API."""
    cmd = [
        "curl", "-s", "-X", "POST",
        "-H", f"x-goog-api-key: {TOKEN}",
        "-H", "Content-Type: application/json",
    ]
    if body:
        cmd.extend(["-d", json.dumps(body)])
    cmd.append(f"{BASE}{path}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return {"error": r.stderr}
    try:
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        return {}

def list_all_sessions():
    """List all sessions with pagination."""
    all_sessions = []
    page_token = None
    
    while True:
        params = "?pageSize=100"
        if page_token:
            params += f"&pageToken={page_token}"
        
        data = api_get(f"/sessions{params}")
        if "error" in data:
            print(f"Error: {data['error']}")
            break
        
        sessions = data.get("sessions", [])
        all_sessions.extend(sessions)
        
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    
    return all_sessions

def find_awaiting_feedback(sessions):
    """Filter sessions for SheepVibes in AWAITING_USER_FEEDBACK state."""
    results = []
    for s in sessions:
        state = s.get("state", "")
        source = s.get("sourceContext", {}).get("source", "")
        if state == "AWAITING_USER_FEEDBACK" and "SheepVibes" in source:
            results.append(s)
    return results

def close_session(session_id, reason="Duplicate PRs have been cleaned up. Closing session."):
    """Send a message to close the session."""
    path = f"/sessions/{session_id}:sendMessage"
    body = {"prompt": reason}
    result = api_post(path, body)
    return result

def main():
    if not TOKEN:
        print("ERROR: JULES_API_KEY not set", file=sys.stderr)
        sys.exit(1)
    
    mode = len(sys.argv) > 1 and sys.argv[1] in ("close", "list", "dry-run") and sys.argv[1] or "list"
    
    print("Fetching all sessions...")
    all_sessions = list_all_sessions()
    print(f"Total sessions fetched: {len(all_sessions)}")
    
    # Find SheepVibes sessions in AWAITING_USER_FEEDBACK
    awaiting = find_awaiting_feedback(all_sessions)
    print(f"\nSheepVibes sessions in AWAITING_USER_FEEDBACK: {len(awaiting)}")
    
    for s in awaiting:
        sid = s.get("id", "?")
        title = s.get("title", "?")
        url = s.get("url", "?")
        source = s.get("sourceContext", {}).get("source", "?")
        print(f"  Session {sid}: {title}")
        print(f"    URL: {url}")
        print(f"    Source: {source}")
    
    if mode == "list":
        return
    
    if not awaiting:
        print("\nNo sessions to close.")
        return
    
    if mode == "dry-run":
        print(f"\n[DRY RUN] Would close {len(awaiting)} sessions")
        return
    
    # Close sessions
    print(f"\nClosing {len(awaiting)} sessions...")
    closed = []
    failed = []
    
    for s in awaiting:
        sid = s.get("id", "?")
        title = s.get("title", "?")
        
        # Try to send a closing message
        result = close_session(sid)
        if "error" in result:
            print(f"  Session {sid}: FAILED - {result['error'][:80]}")
            failed.append(sid)
        else:
            print(f"  Session {sid}: Sent close message - {title}")
            closed.append(sid)
    
    print(f"\nResults:")
    print(f"  Closed: {len(closed)}")
    print(f"  Failed: {len(failed)} {failed}")

if __name__ == "__main__":
    main()
