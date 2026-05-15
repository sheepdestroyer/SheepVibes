# SheepVibes Kanban Cleanup and Repository Restoration Plan

**Date:** 2026-05-15
**Context:** The SheepVibes kanban-driven PR review process failed. All PRs were merged without following the required review loop (inventory -> dedupe -> review -> merge -> close-redundant). This plan restores a clean repository state and establishes a bulletproof process for future Jules PRs.

---

## Goal

1. Identify every PR merged after 2026-02-22 17:02:14 CET (the merge of #323).
2. Roll back `main` to that known-good commit.
3. Close all remaining open PRs.
4. End and remove all active Jules sessions for `sheepdestroyer/SheepVibes`.
5. Write and commit a clean, thorough process document for future Jules PRs.

---

## Current Context / Assumptions

- **Repository:** `sheepdestroyer/SheepVibes` on GitHub.
- **Last known-good commit on `main`:** `07e67b2` — Merge pull request #323 "Fix middle-click mark as read" (2026-02-22 18:02:14 +0100).
- **Current HEAD on `main`:** `95de23d` — Merge pull request #465 (2026-05-11 04:54:33 +0200).
- **~36 PRs** were merged after the cutoff without proper kanban gatekeeping.
- **4 open PRs** remain in-flight and must be abandoned.
- **Jules sessions** may still be active/pending for this repo and need cleanup.
- **Kanban board** `sheepvibes` exists at `~/.hermes/kanban/boards/sheepvibes/kanban.db` and may have stale tasks.

---

## Step-by-Step Plan

### Phase 1 — Inventory and Verification (Read-only)

**1.1 Verify the rollback target**
- Run: `git log --oneline -1 07e67b2`
- Confirm it is PR #323 merge.
- Confirm the test suite passes at this commit:
  ```bash
  git stash
  git checkout 07e67b2
  cd backend && pip install -r requirements.txt -r requirements-dev.txt
  CACHE_REDIS_PORT=<redis_port> python -m pytest -v
  ```

**1.2 Document all merged PRs after cutoff**
Already identified via `gh pr list`. Produce a final ordered list (oldest -> newest):

| # | Title | Merged At | Branch |
|---|-------|-----------|--------|
| 314 | chore(deps): bump flask from 3.1.2 to 3.1.3 | 2026-02-22 17:05 | dependabot/pip/backend/main/flask-3.1.3 |
| 315 | chore(deps): bump filelock from 3.24.2 to 3.24.3 | 2026-02-22 17:06 | dependabot/pip/backend/main/filelock-3.24.3 |
| 310 | chore: remove dead code comments from feed_service.py | 2026-02-22 17:15 | cleanup-dead-code-feed-service-... |
| 312 | [testing improvement] Add unit tests for cache utility functions | 2026-02-22 18:55 | testing-improvement-cache-utils-... |
| 328 | Add test for feed deletion error handling | 2026-02-24 09:36 | test-feed-delete-errors-... |
| 336 | Fix FeedItem.validate_datetime_utc Docstring and Add Tests | 2026-02-24 09:24 | fix-feeditem-validator-docstring-... |
| 313 | Refactor renderTabs to avoid array mutation | 2026-02-24 09:37 | refactor-render-tabs-mutation-... |
| 329 | [TEST] Add IntegrityError Test for Tab Creation | 2026-02-24 09:57 | tests/tab-creation-integrity-error-... |
| 330 | Refactor _enforce_feed_limit for better testability | 2026-02-24 11:19 | jules-11144106913590746397-d84f73b0 |
| 349 | Replace standard XML parser with defusedxml for security | 2026-02-24 18:28 | security-defusedxml-migration-... |
| 384 | Sentinel: [MEDIUM] Fix input length validation missing in API endpoints | 2026-05-11 01:56 | sentinel/input-length-validation-... |
| 415 | Bolt: Cache widgets by tab to optimize toggleWidgetsVisibility | 2026-05-10 02:08 | bolt/cache-widgets-by-tab-... |
| 421 | build(deps): bump sqlalchemy from 2.0.46 to 2.0.49 | 2026-05-10 02:09 | dependabot/pip/backend/main/sqlalchemy-2.0.49 |
| 423 | Sentinel: [HIGH] Fix DOM-based XSS risk by removing innerHTML | 2026-05-11 02:18 | sentinel/fix-dom-xss-risk-... |
| 427 | Bolt: Optimize OPML import feed URL retrieval | 2026-05-11 02:10 | bolt/optimize-url-retrieval-... |
| 429 | Bolt: Add index to Feed.tab_id | 2026-05-10 02:10 | bolt-add-index-to-tab-id-... |
| 434 | build(deps): bump filelock from 3.24.3 to 3.29.0 | 2026-05-10 02:07 | dependabot/pip/backend/main/filelock-3.29.0 |
| 437 | build(deps): update flask-caching requirement from >=2.1.0 to >=2.4.0 | 2026-05-10 01:54 | dependabot/pip/backend/main/flask-caching-gte-2.4.0 |
| 442 | Bolt: Optimized datetime serialization | 2026-05-10 02:27 | bolt/optimized-datetime-serialization-... |
| 443 | Bolt: Optimize get_feed_items query by bypassing ORM instantiation | 2026-05-10 02:08 | bolt-optimize-get-feed-items-... |
| 445 | Sentinel: [HIGH] Fix CSRF vulnerability on OPML import | 2026-05-10 01:52 | sentinel-csrf-xss-hardening-... |
| 447 | Bolt: optimize bulk cache invalidation | 2026-05-10 02:12 | jules-13544357218954574306-3754dd66 |
| 456 | Add X-XSS-Protection HTTP header | 2026-05-11 01:45 | sentinel-xss-protection-header-... |
| 457 | Bolt: Optimize cache invalidation with bulk operations | 2026-05-11 01:57 | bolt-cache-invalidation-... |
| 458 | Bolt: optimize fallback item insertion with nested transactions | 2026-05-11 01:39 | bolt-perf-save-items-individually-... |
| 459 | Bolt: Record querySelectorAll micro-optimization learning | 2026-05-11 02:25 | bolt-optimize-feed-update-... |
| 460 | Bolt: Add database index on Feed url | 2026-05-11 02:31 | perf-index-feed-url-... |
| 462 | Sentinel: Remove unsafe-inline from CSP style-src | 2026-05-11 02:37 | pr385-csp-merged |
| 463 | Bolt: Optimize feed item deduplication using targeted IN queries | 2026-05-11 02:39 | pr378-dedup-merged |
| 464 | Sentinel: Fix Stored XSS and SSRF vulnerability in feed endpoints | 2026-05-11 02:41 | pr371-xss-merged |
| 465 | Sentinel: Fix weak file type validation in OPML import | 2026-05-11 02:54 | pr367-opml-merged |
| 331 | Refactor initializeTabs to use validateActiveTab helper | 2026-05-12 11:57 | refactor-initialize-tabs-... |
| 333 | Refactor _determine_target_tab for improved readability | 2026-05-13 10:25 | refactor-determine-target-tab-... |
| 339 | Refactor get_feeds_for_tab to tab_service | 2026-05-13 10:22 | refactor-get-feeds-for-tab-... |
| 340 | Refactor SafeHTTP(S)Connection to use SafeConnectionMixin | 2026-05-13 10:21 | refactor-safe-connection-mixin-... |
| 341 | Add Missing SECRET_KEY Configuration | 2026-05-13 10:21 | security-fix-secret-key-config-... |
| 342 | Missing Exception Test in update_feed_url | 2026-05-13 10:14 | test-feed-update-error-... |
| 344 | Refactor _save_items_individually for better readability | 2026-05-13 10:22 | jules-refactor-feed-service-... |
| 345 | Add unit tests for MessageAnnouncer (SSE) | 2026-05-11 09:40 | test-sse-unit-tests-... |
| 346 | Refactor frontend/js/ui.js to deduplicate feed item rendering logic | 2026-05-11 09:37 | refactor-ui-deduplicate-rendering-... |
| 347 | Refactor createFeedWidget into helper functions | 2026-05-11 09:34 | jules-13974741853378168197-c7f3a946 |

> Note: Dependabot PRs (#314, #315, #421, #434, #437) are **excluded** from rollback. They will be cherry-picked back onto the clean tree after reset.

**1.3 Document all open PRs to close**
| # | Title | Branch |
|---|-------|--------|
| 301 | Bolt: Implement Conditional GET for Feed Fetching | bolt/conditional-get-... |
| 316 | Bolt: Debounce window resize listener | bolt-debounce-resize-... |
| 320 | Sentinel: Add rate limiting to sensitive endpoints | sentinel-rate-limiting-... |
| 332 | Refactor fetch_feed to use create_safe_opener helper | refactor-feed-fetch-handlers-... |

---

### Phase 2 — Rollback `main` to Clean State (Preserving Dependabot)

**2.1 Hard reset local `main` to the cutoff commit**
```bash
git checkout main
git fetch origin
git reset --hard 07e67b2
```

**2.2 Cherry-pick Dependabot PRs back onto the clean tree**
These Dependabot commits must be preserved. Identify their exact merge commit hashes from `git log` and cherry-pick in chronological order:

| PR | Commit (example) | Description |
|----|------------------|-------------|
| #314 | `0d60aa7` | chore(deps): bump flask from 3.1.2 to 3.1.3 |
| #315 | `cbedf8e` | chore(deps): bump filelock from 3.24.2 to 3.24.3 |
| #421 | `a1b8970` | build(deps): bump sqlalchemy from 2.0.46 to 2.0.49 |
| #434 | `80cef39` | build(deps): bump filelock from 3.24.3 to 3.29.0 |
| #437 | `f89b72b` | build(deps): update flask-caching requirement from >=2.1.0 to >=2.4.0 |

```bash
# Verify exact hashes before cherry-picking
git log --oneline --grep="dependabot" 07e67b2..origin/main

# Cherry-pick in chronological order (oldest first)
for commit in 0d60aa7 cbedf8e a1b8970 80cef39 f89b72b; do
  git cherry-pick "$commit" --no-edit || {
    echo "Conflict on $commit - resolve manually"
    exit 1
  }
done
```
> If any cherry-pick conflicts, resolve it (these are typically trivial version-bump conflicts). Abort and reassess if a conflict is non-trivial.

**2.3 Force-push the reconstructed `main`**
```bash
git push --force-with-lease origin main
```
> `--force-with-lease` is safer than `--force`; if someone else pushed since fetch, it aborts.

**2.4 Verify remote matches target**
```bash
git log --oneline -5 origin/main
```
Must show: `07e67b2` + 5 Dependabot cherry-picks.

**2.5 Run the full test suite at the restored commit**
```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
# Start Redis container, capture port, set CACHE_REDIS_PORT
python -m pytest -v
```
If tests fail, debug and fix before proceeding. The cutoff was chosen because #323 was the last known-good merge; if tests fail at `07e67b2`, the cutoff may need adjustment.

**2.6 Clean up local tracking branches**
After force-push, any local branches that were based on post-cutoff `main` are now divergent. List and delete stale locals:
```bash
git branch --merged origin/main  # safe to delete
git branch --no-merged origin/main  # inspect carefully
```

---

### Phase 3 — Close All Open PRs

**3.1 Close the 4 open PRs with a standardized comment**
```bash
for pr in 301 316 320 332; do
  gh pr close "$pr" --repo sheepdestroyer/SheepVibes --comment \
    "Closing as part of process cleanup. Main has been rolled back to pre-Feb-22 state. If still relevant, please rebase and re-open after the new Jules process is enacted."
done
```

**3.2 Clean up orphaned remote branches**
Delete the branches associated with the closed PRs (and any other stale `jules-*`, `sentinel-*`, `bolt-*` branches that are no longer needed):
```bash
gh api repos/sheepdestroyer/SheepVibes/git/refs --paginate | jq -r '.[].ref' | grep refs/heads | sed 's|refs/heads/||' | sort
# Then selectively delete:
gh api -X DELETE repos/sheepdestroyer/SheepVibes/git/refs/heads/BRANCH_NAME
```
> Be careful not to delete `main` or protected branches.

---

### Phase 4 — End and Remove All Jules Sessions

**4.1 List all Jules sessions**
```bash
export JULES_API_KEY=$(grep JULES_API_KEY ~/.hermes/.env | cut -d= -f2 | tr -d '"' | xargs)
curl -s 'https://jules.googleapis.com/v1alpha/sessions?pageSize=50' \
  -H "X-Goog-Api-Key: $JULES_API_KEY" | jq -r '.sessions[] | "\(.id) \(.state) \(.title)"'
```

**4.2 Filter for SheepVibes-related sessions**
Use `jq` or Python to filter sessions where `sourceContext.source` contains `sheepdestroyer/SheepVibes` or `sheepvibes`.

**4.3 Close every matching session**
```bash
for session_id in $SHEEPVIBES_SESSION_IDS; do
  curl -s -X POST "https://jules.googleapis.com/v1alpha/sessions/sessions/${session_id}:close" \
    -H "Content-Type: application/json" \
    -H "X-Goog-Api-Key: $JULES_API_KEY"
  echo "Closed $session_id"
done
```
> Per the Jules API skill, sessions in `AWAITING_USER_FEEDBACK` accumulate if not closed. Closing them prevents future confusion.

**4.4 Verify no SheepVibes sessions remain active**
Re-run the list and confirm zero matches.

---

### Phase 5 — Clean Up Kanban Board

**5.1 Inspect the SheepVibes kanban DB**
```bash
sqlite3 ~/.hermes/kanban/boards/sheepvibes/kanban.db ".tables"
sqlite3 ~/.hermes/kanban/boards/sheepvibes/kanban.db "SELECT id, title, status FROM tasks;"
```

**5.2 Clear or archive all stale tasks**
Since the board was a failure and all PRs were merged without process, mark all tasks as `cancelled` or delete them:
```bash
sqlite3 ~/.hermes/kanban/boards/sheepvibes/kanban.db \
  "UPDATE tasks SET status = 'cancelled' WHERE status IN ('todo','in_progress','review');"
```

**5.3 Optionally reset the board entirely**
If the board schema is simple, consider backing up and recreating:
```bash
cp ~/.hermes/kanban/boards/sheepvibes/kanban.db \
   ~/.hermes/kanban/boards/sheepvibes/kanban.db.bak.$(date +%Y%m%d)
# Then truncate tasks or drop/recreate tables per the kanban schema.
```

---

### Phase 6 — Write the New Jules PR Process Document

**6.1 Create the process document**
Path: `docs/process/jules-pr-workflow.md` (or `.openhands/microagents/jules-pr-process.md` if OpenHands integration is desired).

The document must cover:
1. **Pre-flight checklist** before creating a Jules session:
   - Is there already an open PR for this issue? (deduplication)
   - Is the issue already tracked in the kanban board?
   - Does the issue have a clear, single-scope description?
2. **Jules session creation rules**:
   - Always use `requirePlanApproval: true`.
   - Never use `AUTO_CREATE_PR` unless the plan has been reviewed.
   - Title must follow convention: `[area] Brief description`.
3. **Kanban gating** (the SheepVibes flow):
   - `inventory` -> `dedupe` -> `review` -> `merge` -> `close-redundant`
   - A PR may NOT be merged until:
     - It has 0 unresolved review comments.
     - E2E tests pass.
     - CI passes.
     - It has been explicitly moved to the `merge` column.
4. **Branch naming**:
   - Jules branches: `jules-<session-id>-<hash>`
   - Human branches: `<type>/<description>`
5. **Post-merge cleanup**:
   - Close the Jules session.
   - Delete the branch.
   - Update the kanban board.
   - Close any duplicate/redundant PRs.
6. **Escalation / failure handling**:
   - If Jules gets stuck in `AWAITING_USER_FEEDBACK` for >24h, close the session and reassess.
   - If a PR review reveals major issues, move back to `review` and re-trigger Jules with new instructions.

**6.2 Update AGENTS.md if needed**
If there are references to the old kanban process, update them to point to the new document.

**6.3 Update CHANGELOG.md**
Add an entry under a new "Process" section documenting the cleanup and the new workflow enactment date.

**6.4 Update TODO.md**
Mark any stale TODOs related to the rolled-back PRs as cancelled or removed.

---

### Phase 7 — Final Validation

**7.1 Verify repository state**
- `origin/main` == `07e67b2`
- No open PRs remain (closed in Phase 3)
- No active Jules sessions for SheepVibes (Phase 4)
- Kanban board is clean (Phase 5)

**7.2 Verify tests pass**
Run the full backend test suite one final time at the restored `main`.

**7.3 Commit the process document**
The process document itself is a file addition; commit it to the restored `main`:
```bash
git checkout -b docs/jules-pr-process
git add docs/process/jules-pr-workflow.md
git commit -m "docs: add Jules PR process workflow (#PROCESS-2026-05-15)"
git push origin docs/jules-pr-process
# Open a manual PR and merge it via the new process as the first test.
```

---

## Files Likely to Change

- `docs/process/jules-pr-workflow.md` (new)
- `CHANGELOG.md` (update)
- `TODO.md` (update)
- `AGENTS.md` (possible update if stale process refs exist)
- `~/.hermes/kanban/boards/sheepvibes/kanban.db` (mutation)
- Remote `main` on GitHub (force-push rewrite)

---

## Tests / Validation

- [ ] `origin/main` commit hash matches `07e67b2`.
- [ ] `python -m pytest -v` passes in `backend/` at restored `main`.
- [ ] All open PRs (#301, #316, #320, #332) show state `CLOSED`.
- [ ] Zero active Jules sessions for SheepVibes repo.
- [ ] Kanban DB contains no `todo`/`in_progress`/`review` tasks.
- [ ] New process document is committed and readable.

---

## Risks, Tradeoffs, and Open Questions

| Risk | Mitigation |
|------|------------|
| **Force-push rewrites public history.** Anyone with a local clone will need to rebase or re-clone. | Communicate clearly. Only `main` is affected; feature branches can be rebased. This is a known repo-recovery technique. |
| **Tests at `07e67b2` may fail due to environment drift** (e.g., dependency updates in requirements.txt that were rolled back). | The 5 Dependabot cherry-picks restore the dependency bumps. If tests still fail, investigate the cutoff commit itself. |
| **Cherry-picking Dependabot commits may conflict** if other PRs touched the same files (requirements.txt, etc.). | Dependabot changes are usually isolated to version strings. If conflicts occur, resolve manually or skip that cherry-pick and re-apply the bump manually. |
| **Jules sessions may have created branches that are not PRs.** | List and delete orphaned `jules-*` branches during Phase 3 cleanup. |
| **Open PR authors may want to salvage work.** | The close comment explicitly invites rebase + re-open. Branches are not deleted immediately. |

**Open Questions:**
- Should the cutoff be `07e67b2` (PR #323) or an earlier commit if tests fail at that point?
- Should the new process document live in `docs/` or `.openhands/microagents/`?
- Should we disable Dependabot auto-merge as part of the new process?

---

## Execution Commands Summary

```bash
# Phase 2: Rollback
git checkout main
git fetch origin
git reset --hard 07e67b2
git push --force-with-lease origin main

# Phase 3: Close open PRs
for pr in 301 316 320 332; do
  gh pr close "$pr" --repo sheepdestroyer/SheepVibes \
    --comment "Closing as part of process cleanup. Main rolled back to pre-Feb-22 state. Re-open if still relevant after new process enactment."
done

# Phase 4: Jules session cleanup
export JULES_API_KEY=$(grep JULES_API_KEY ~/.hermes/.env | cut -d= -f2 | tr -d '"' | xargs)
curl -s 'https://jules.googleapis.com/v1alpha/sessions?pageSize=50' \
  -H "X-Goog-Api-Key: $JULES_API_KEY" | jq -r '.sessions[] | select(.sourceContext.source | contains("sheepvibes")) | .id' | while read sid; do
  curl -s -X POST "https://jules.googleapis.com/v1alpha/sessions/sessions/${sid}:close" \
    -H "Content-Type: application/json" -H "X-Goog-Api-Key: $JULES_API_KEY"
done

# Phase 5: Kanban cleanup
sqlite3 ~/.hermes/kanban/boards/sheepvibes/kanban.db \
  "UPDATE tasks SET status = 'cancelled' WHERE status IN ('todo','in_progress','review');"
```
