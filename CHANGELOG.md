# Timestamped Changelog maintained by agents when working on this repository

## 2026-08-06

- **Fix: Prod feed refresh investigation & resolution**
  - **Deduplication Logic Fix**: Fixed a bug in `_process_single_entry` in `backend/feed_service.py` where fallback link-matching (`existing_items_by_link`) hijacked existing DB items with distinct GUIDs when feed entries shared a common URL (e.g., `Kernel.org`). Now, candidate items matched by link are only updated if their GUID matches or is undefined, allowing new items with distinct GUIDs to be properly inserted.
  - **Network Timeout Extension**: Increased `DEFAULT_FEED_FETCH_TIMEOUT` in `backend/feed_service.py` from 10s to 20s (configurable via `FEED_FETCH_TIMEOUT`), resolving timeout failures for slower feeds like *Dumbing of Age*.
  - **Production DB Feed URL Updates**: Updated broken/deprecated feed URLs in `tests/test_feeds.opml` and the production database:
    - *Phoronix* (ID 92): Updated from stale Feedburner URL `http://feeds.feedburner.com/Phoronix` to direct RSS URL `https://www.phoronix.com/rss.php`.
    - *Techno-Science.net* (ID 58): Updated from 404 URL `http://www.techno-science.net/include/news.rss` to active URL `https://www.techno-science.net/include/news.xml`.
    - *NYT World News* (ID 77): Updated from dead proxy host `rssproxy.migor.org` to direct RSS URL `https://rss.nytimes.com/services/xml/rss/nyt/World.xml`.
  - **Validation & Container Rebuild**: Rebuilt the container image, restarted `sheepvibes-app.service`, and verified 100% success rate (53/53 feeds updated, 798+ new items added). Added unit tests in `tests/unit/test_feed.py`.

## 2026-08-05

- **Release: All 13 Open Pull Requests Merged & Verified**
  - **E2E Infrastructure** (PR #520, Issue #519): Created `tests/e2e/conftest.py` with `live_server` fixture (Flask subprocess management, `start_new_session=True`, `DEVNULL` streams, `TEST_BASE_URL` override support) and 1920x1080 viewport. Integrated Playwright headless Chromium into CI.
  - **Frontend Security** (PR #518): URL scheme allowlist sanitization (`sanitizeUrl`), parameter encoding (`encodeURIComponent`), and download link `rel="noopener noreferrer"`.
  - **Backend Security** (PR #517): Feed URL scheme validation (`http:`, `https:`), RFC 6066 SSL SNI port handling, and XML 1.0 control character filtering.
  - **Infrastructure & CI Parity** (PR #516): Dynamic Redis port handling, pinned GitHub Action tags, `Containerfile` `HEALTHCHECK`/`chown`, strict shell execution flags.
  - **Frontend UX & Accessibility** (PR #515): WAI-ARIA tab semantics (`role="tabpanel"` on `#feed-grid`), `try...finally` throttle error handling, minimum 44px touch targets.
  - **Backend Reliability** (PR #513): Pre-extracted `tab_id` preventing `DetachedInstanceError` on rollback, `Feed.tab_id` DB index, cache invalidation on tab deletion, background scheduler session cleanup.
  - **Subpath Routing & Quadlet Port Fix** (PR #500): Fixed subpath API routing and Quadlet configuration.
  - **Code Refactoring** (PR #488): Refactored `_collect_new_items` in `backend/feed_service.py` to fix long function issue.
  - **Dependency Updates** (PRs #508, #507, #503, #499, #495): Upgraded `filelock` (3.32.2), `feedparser` (6.0.14), `actions/setup-python` (v7), `flask-caching` (>=2.4.1), and `apscheduler` (3.11.3).

## 2026-05-15


- **Process: Repository cleanup and new Jules PR workflow enacted**
  - Rolled back `main` to `07e67b2` (2026-02-22, PR #323) to undo 36+ PRs merged without review.
  - Preserved 5 Dependabot dependency bumps by cherry-picking them onto the clean tree.
  - Closed 4 open PRs (#301, #316, #320, #332) with cleanup comments.
  - Deleted 253 active/queued Jules sessions targeting SheepVibes via the Jules API.
  - Cancelled 16 stale tasks on the SheepVibes kanban board.
  - Enacted `docs/process/jules-pr-workflow.md` with mandatory five-gate review loop.
  - Full test suite passes: 121 passed, 2 skipped.

## 2026-02-22

- **Fix: Middle-click to mark as read**
  - Added `auxclick` event listener to feed item links in `frontend/js/ui.js` to ensure items are marked as read when opened via middle-click.

## 2026-01-29

- **Feat: Robust OPML Import & Feed Refresh Progress**
  - **Iterative Processing**: Migrated OPML parsing to a stack-based iterative approach in `backend/feed_service.py` to prevent recursion depth issues.
  - **Weighted Progress**: Implemented a 50/50 continuous progress scale for OPML imports (processing vs. fetching).
  - **Security (XSS Prevention)**: Hardened `xmlUrl` validation to allow only `http` and `https` schemes.
  - **SSE Reliability**: Added `progress_complete` signals to all service exit paths and normalized tab ID types in the frontend.
  - **Code Cleanup**: Removed redundant recursive logic and unused imports from `backend/blueprints/opml.py`.

## 2026-01-26 (v0.4.0-pre)

- **Architecture: Modularization Overhaul (Backend & Frontend)**
  - **Backend**: Split monolithic `app.py` into Flask Blueprints (`feeds`, `opml`, `tabs`) for better separation of concerns.
  - **Frontend**: Refactored `script.js` into ES6 modules (`api.js`, `ui.js`, `utils.js`, `app.js`) to improve maintainability.
  - **Migration**: Added new SQLAlchemy naming convention to fix constraint naming issues across different DBs.

- **Fix: Critical Data Integrity & Deduplication**
  - **GUID Priority**: Updated `feed_service` to prioritize `id` over `link` for GUIDs. This prevents data loss for feeds (like Kernel.org) where multiple items share the same URL.
  - **Composite Constraints**: Replaced global `guid` uniqueness with `(feed_id, guid)` composite constraint to allow same-GUID items in different feeds.
  - **Graceful Failures**: Implemented fallback to individual item insertion if batch commits fail due to integrity errors.

- **Feat: Dev Experience & Quality of Life**
  - **Hot Reloading**: Updated dev container to use `flask run` (Debug Mode) instead of Gunicorn, enabling instant code updates.
  - **Secure Links**: Added `rel="noopener noreferrer"` to all external feed links to prevent tabnabbing.
  - **Performance**: Optimized SSE updates to prevent full-page flicker and scroll position loss.
  - **Cache Optimization**: Granular cache invalidation for tabs and feeds to reduce unnecessary Redis workload.

## 2026-01-11

- **Feat: Add `dev_manager.sh` for Podman-based local development**
  - Created `scripts/dev_manager.sh` to automate building, running, and cleaning the dev environment (App + Redis).
  - Updated `README.md` with usage instructions for the new script.
  - Updated `AGENTS.md` to recommend the tool for future agents.

## 2025-10-08

- **Documentation: Added code review cycle guidelines**
  - Created comprehensive guide for maintaining PR descriptions across review cycles
  - Added template structure for multi-cycle PR descriptions
  - Documented best practices for preserving context and incremental updates
  - Updated TODO.md to track completion

- **Migration: Upgrade project to Python 3.14**
  - Updated GitHub workflow run-tests.yml to use Python 3.14
  - Updated Containerfile to use Python 3.14-slim base image
  - Updated documentation to reflect Python 3.14 migration
## 2025-10-07

- **Feat(frontend): Move unread counter to left of edit and close buttons**
  - Added edit button (✎) to feed widgets alongside existing delete button
  - Created button container to group edit, delete buttons and unread counter
  - Repositioned unread counter from title area to left of buttons in button container
  - Updated CSS styling for new button container layout with flexbox
  - Added placeholder handleEditFeed function for future implementation

- **Fix: Fix critical error handling bugs and complete code review feedback**
  - **Fixed `handleMarkItemRead`**: Removed unnecessary success check since `fetchData` throws on error - the UI was not updating items as read
  - **Fixed `handleDeleteTab`**: Removed unnecessary success check since `fetchData` throws on error - the UI was not updating after tab deletion
- **Improved `API_BASE_URL` detection**: Now uses `window.location.hostname` instead of `window.location.origin.includes('localhost')` for more robust localhost detection
- **Removed dead code**: Eliminated unreachable error handling in `handleRefreshAllFeeds`
- **Added radix parameter**: Used `parseInt(feedIdInput.value, 10)` to prevent unexpected octal parsing behavior

## 2025-10-06

- **Feat: Make each widget's feed URL editable**
  - Added PUT endpoint `/api/feeds/<feed_id>` for updating feed URLs and properties
  - Added edit button (✎) to each feed widget in the frontend
  - Implemented modal dialog for editing feed URLs with validation
  - Added comprehensive tests for the new functionality
  - Feed name and site link are automatically updated when URL is changed
- **Fix: Addressed all Gemini Code Assist review comments for PR #100**
  - Fixed backend performance issue by replacing redundant `fetch_and_update_feed` call with direct `process_feed_entries` to avoid duplicate network requests
- Updated frontend API configuration to use relative paths for production deployment
- Fixed frontend error handling syntax and improved user experience in edit modal

## 2025-07-26

- **Fix(feed_service): Use entry link as GUID to prevent UNIQUE constraint errors**
  - The MIT Technology Review feed was failing to update because it was providing the same GUID for multiple different articles. This was causing a UNIQUE constraint failure in the database.
  - This change modifies the `feed_service` to always use the entry's link as the GUID. The link is a reliable and unique identifier for each article, which will prevent this issue from happening in the future.
