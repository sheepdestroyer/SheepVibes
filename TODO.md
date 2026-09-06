# SheepVibes - Implementation Plan (TODO)

This document outlines the steps to build the SheepVibes RSS aggregator.

## 2026-09-06 Custom Feed Names (Issue #552)

*   [x] **Feat: Ability to edit feed name and assign custom names:**
    *   [x] Remove `readonly` attribute from `#edit-feed-name` in `#edit-feed-modal` in `frontend/index.html`.
    *   [x] Update modal help text to explain that entering a name sets a custom name, or leaving empty auto-derives from the feed title.
    *   [x] Update `frontend/js/ui.js` (`openEditFeedModal`, `updateFeedWidgetTitle`) and `frontend/js/app.js` (`handleEditFeedSubmit`) to populate `#edit-feed-name`, send payload `{ url, name }` to `api.updateFeed`, and immediately update the widget's title in the DOM.
    *   [x] Update `frontend/js/api.js` to support both object `{ url, name }` and separate arguments in `api.updateFeed`.
    *   [x] Update `backend/blueprints/feeds.py` (`PUT /api/feeds/<feed_id>`):
        *   [x] Validate and sanitize custom feed names (`sanitize_feed_name`: HTML entity unescaping, control char removal, whitespace normalization, 200 char truncation).
        *   [x] Allow updating feed name without unnecessary network refetches if the feed URL has not changed.
        *   [x] If custom name is empty or whitespace, re-derive from feed (or preserve existing name if fetch fails).
        *   [x] Invalidate cache (`invalidate_tab_feeds_cache`) and enforce tenant isolation.
    *   [x] Add unit test suites in `frontend/js/ui.test.js`, `frontend/js/api.test.js`, `tests/unit/test_feed.py`, and `tests/unit/test_app.py`.
    *   [x] Add Playwright E2E test suite in `tests/e2e/test_edit_feed.py`.
    *   [x] Validate test suites across Pytest unit (267/267), Vitest (60/60), and Playwright E2E (17 passed, 1 skipped).

## 2026-09-06 Container Log Priority Splitter Integration

*   [x] **Align container stderr logging with syslog priority via unified splitter:**
    *   [x] Mount `/mnt/DATA/boy/prod/infra/bin/log-priority-splitter.sh` with `:ro,z` into `pod/sheepvibes-app.container` and set as `Entrypoint`, wrapping `/app/scripts/entrypoint.sh`.
    *   [x] Mount `/mnt/DATA/boy/prod/infra/bin/log-priority-splitter.sh` with `:ro,z` into `pod/sheepvibes-rssbridge.container` and set as `Entrypoint`, wrapping `/app/docker-entrypoint.sh`.
    *   [x] Prevent non-error runtime outputs (Gunicorn worker boots, Alembic migrations, PHP-FPM notices, access logs) from being mapped to syslog `PRIORITY=3` (`err`) by `conmon`.
    *   [x] Update unit tests in `tests/unit/test_rss_bridge.py` to verify quadlet configuration and splitter volume mounts.
    *   [x] Validate test suites across Pytest unit (258/258), Vitest (58/58), and Playwright E2E.

## 2026-09-06 RSS-Bridge Deployment & RSS-Less Page Feed Bridging (Issue #550)

*   [x] **Fix RSS-Bridge feed title generation and relative entry links:**
    *   [x] Enhance `pod/bridges/GenericChangelogBridge.php` to extract page metadata (`og:site_name`, `<title>`, `og:title`, favicon) and implement dynamic `getName()`, `getURI()`, and `getIcon()` to avoid fallback to generic bridge name.
    *   [x] Update `pod/bridges/GenericChangelogBridge.php` to resolve relative entry URIs and enclosure URLs using `urljoin($baseUrl, $uri)` instead of plain `defaultLinkTo()`.
    *   [x] Improve entry title extraction in `GenericChangelogBridge.php` to prioritize semantic headings (`h1`..`h5`, `.post-title`) and parse clean version string prefixes.
    *   [x] Update `backend/feed_name_utils.py` to identify generic bridge placeholder names, strip inverted changelog boilerplate delimiters, and expand `KNOWN_DOMAIN_BRANDS` (`antigravity.google`, `jules.google`, `lucebox.com`).
    *   [x] Update `backend/feed_service.py` to canonicalize generic bridge titles and resolve relative entry links against base page URL.
    *   [x] Add unit tests in `tests/unit/test_feed_name_utils.py` and `tests/unit/test_rss_bridge.py`.
    *   [x] Validate full test suites across unit tests (258/258), Playwright E2E (16 passed, 1 skipped), and Vitest (58/58).
*   [x] **Deploy RSS-Bridge in pod and support RSS-less pages:**
    *   [x] Define Podman Quadlet container `pod/sheepvibes-rssbridge.container` running `docker.io/rssbridge/rss-bridge:latest` on the shared pod network.
    *   [x] Mount custom PHP bridges from `pod/bridges/` into `/config` in the RSS-Bridge container.
    *   [x] Implement generic automatic bridge `pod/bridges/GenericChangelogBridge.php` to extract changelog, release, and blog entries from arbitrary web pages via JSON-LD schema, container selectors, and heading patterns without site-specific code.
    *   [x] Archive earlier site-specific custom bridges into `pod/bridges_backup/` (`LuceboxBridge.php.bak`, `AntigravityChangelogBridge.php.bak`, `JulesChangelogBridge.php.bak`) to standardize on the single dynamic `GenericChangelogBridge.php`.
    *   [x] Support GitHub Releases feeds (`https://github.com/NousResearch/hermes-agent/releases`) via RSS-Bridge's built-in `GithubReleaseBridge`.
    *   [x] Update `pod/sheepvibes-app.container` with `Wants`/`After=sheepvibes-rssbridge.container` and `Environment=RSS_BRIDGE_URL=http://localhost:80`.
    *   [x] Update `scripts/dev_manager.sh` to spin up `sheepvibes-dev-rssbridge` alongside App and Valkey, and clean up on teardown.
    *   [x] Update `scripts/deploy_pod.sh` to install Quadlet configuration and deploy custom bridge files including `GenericChangelogBridge.php`.
    *   [x] Integrate RSS-Bridge into `backend/feed_service.py` with `RSS_BRIDGE_URL` configuration, safe SSRF loopback routing for trusted RSS-Bridge host, HTML `<link rel="alternate">` autodiscovery, automatic delegation to matching bridges, and seamless fallback to `GenericChangelogBridge` for RSS-less URLs.
    *   [x] Add unit test suite in `tests/unit/test_rss_bridge.py` verifying URL validation, SSRF protection, feed delegation, custom bridge parsing, and GenericChangelogBridge fallback.
    *   [x] Validate full test suite (Pytest backend unit, Playwright E2E, Vitest frontend).

## 2026-09-05 Parallelized Testing

*   [x] **Parallelize pytest runs by default with `-n auto`:**
    *   [x] Add `pytest-xdist>=3.8.0` to `backend/requirements-dev.txt`.
    *   [x] Configure `addopts = -n auto -v --strict-markers` in `tests/pytest.ini`.
    *   [x] Update `tests/e2e/conftest.py` with worker-isolated ports and SQLite database files to support fully concurrent Playwright E2E execution without collision.
    *   [x] Add unit test coverage in `tests/unit/test_e2e_conftest.py` for worker offset calculation, dynamic port assignment, database path isolation, and configuration validation.
    *   [x] Update documentation in `TESTING.md`.
    *   [x] Validate full test suites across unit tests (233/233), Playwright E2E (16 passed, 1 skipped), and Vitest (58/58).

## 2026-08-31 Review Work

*   [x] **PR #545: Route WARNING logs to stdout and reserve stderr for ERROR/CRITICAL.**
    *   [x] Align logging stream routing with LLM-Routing convention: send `DEBUG`, `INFO`, and `WARNING` to `sys.stdout` (`MaxLevelFilter(logging.WARNING)`).
    *   [x] Restrict `sys.stderr` to `logging.ERROR` and `logging.CRITICAL` so systemd journald and conmon do not map expected `WARNING`s to syslog `PRIORITY=3` (`err`).
    *   [x] Update unit tests in `tests/unit/test_app.py` for stream-to-level verification.
    *   [x] Validate full test suite: 227/227 Pytest unit tests, 58/58 Vitest frontend tests, and 16 passed (1 skipped) Playwright E2E tests.
*   [x] **PR #544: Graceful feed fetch error logging and warning-level handling.**
    *   [x] Catch expected network/socket exceptions (`URLError`, `TimeoutError`, `socket.timeout`, `ConnectionRefusedError`, `OSError`, `http.client.HTTPException`) and log as concise `WARNING`s without full tracebacks.
    *   [x] Downgrade `_process_fetch_result` null feed dispatch log from `ERROR` to `WARNING`.
    *   [x] Preserve `logger.exception` at `ERROR` level for unexpected internal application errors.
    *   [x] Add unit test coverage for network warnings, unexpected error tracebacks, and fetch result logging in `tests/unit/test_feed.py`.
    *   [x] Validate full test suite: 227/227 Pytest unit tests, 58/58 Vitest frontend tests, and 16 passed (1 skipped) Playwright E2E tests.

## 2026-08-30 Review Work

*   [x] **PR #542: Route application log severities by stream without removing host handlers.**
    *   [x] Preserve unrelated Gunicorn, test-capture, and host logging handlers.
    *   [x] Restore root logging state in stream-routing tests and cover handler preservation.
    *   [x] Document stream routing as a container-runtime/systemd convention.
    *   [x] Validate full backend unit tests (219/219), Playwright E2E tests (16 passed, 1 skipped), and frontend Vitest tests (58/58).

## Phase 0: Project Setup & Core Backend

*   [x] Initialize project structure (directories for backend, frontend, docs, etc.).
*   [x] Set up Python virtual environment (`venv`).
*   [x] Install initial Python dependencies (`Flask`, `feedparser`, `APScheduler`, `SQLAlchemy`).
*   [x] Create a basic Flask application (`app.py`).
*   [x] Define database schema/models (using `SQLAlchemy`):
    *   `Tabs` (id, name, order)
    *   `Feeds` (id, tab_id, name, url, last_updated_time)
    *   `FeedItems` (id, feed_id, title, link, published_time, fetched_time, is_read)
*   [x] Implement basic database initialization logic.
*   [x] Create initial `Containerfile` for Podman (Python base image, install dependencies, expose port).
*   [x] Set up basic logging.
*   [x] Add `.gitignore`.

## Phase 1: Feed Fetching & Processing

*   [x] Create a service/module for fetching and parsing RSS/Atom feeds using `feedparser`.
    *   Handle potential errors during fetching/parsing (timeouts, invalid URLs, bad feed formats).
*   [x] Implement logic to store/update feed details and new items in the database.
    *   Avoid duplicating existing items (check GUIDs or links).
    *   Update `last_updated_time` for the feed.
*   [x] Set up `APScheduler` as a background task within the Flask app (or as a separate process if preferred).
    *   Schedule a recurring job to fetch updates for all configured feeds.
    *   Make the interval configurable (e.g., every 15 minutes).
*   [x] Implement initial backend API endpoints (using Flask):
    *   `GET /api/tabs`: List all tabs.
    *   `GET /api/tabs/<tab_id>/feeds`: List feeds for a specific tab.
    *   `GET /api/feeds/<feed_id>/items`: List recent items for a specific feed (with limit/pagination).

## Phase 2: Basic Frontend Structure & Display

*   [x] Create basic HTML structure (`index.html`).
    *   [x] Include placeholders for tabs.
    *   [x] Include a container for the feed widget grid.
*   [x] Create basic CSS (`style.css`) for layout:
    *   [x] Style the tab bar.
    *   [x] Implement a CSS Grid or Flexbox layout for the feed widgets.
    *   [x] Style individual feed widgets (borders, padding, header, item list).
*   [x] Write Vanilla JavaScript (`script.js`) to:
    *   [x] Fetch tabs from `/api/tabs` on page load and render them.
    *   [x] Fetch feeds for the initially active tab (`/api/tabs/<tab_id>/feeds`).
    *   [x] For each feed, fetch its items (`/api/feeds/<feed_id>/items`).
    *   [x] Render the feed widgets dynamically in the grid, populating them with titles and timestamps.
    *   [x] Handle switching between tabs (fetch and render feeds for the selected tab).

## Phase 3: Interactivity & Core Features

*   [x] **Feed Management (Backend API):**
    *   [x] `POST /api/feeds`: Add a new feed (URL, optionally associate with a tab). Backend should fetch initial data upon adding.
    *   [x] `DELETE /api/feeds/<feed_id>`: Remove a feed.
    *   [x] `PUT /api/feeds/<feed_id>`: Update feed URL and properties.
*   [x] **Feed Management (Frontend UI):**
    *   [x] Add a "+" button or form to input a feed URL.
    *   [x] Implement JS to call the `POST /api/feeds` endpoint.
    *   [x] Add a "close" (X) button to each feed widget.
    *   [x] Implement JS for the close button to call `DELETE /api/feeds/<feed_id>` and remove the widget from the DOM.
    *   [x] Add an edit (✎) button to each feed widget.
    *   [x] Position unread counter to the left of edit and close buttons.
    *   [x] Implement JS for the edit button to call `PUT /api/feeds/<feed_id>` and update the feed URL.
*   [x] **Tab Management (Backend API):**
    *   [x] `POST /api/tabs`: Create a new tab.
    *   [x] `DELETE /api/tabs/<tab_id>`: Delete a tab (handle associated feeds - delete them or move to default?).
    *   [x] `PUT /api/tabs/<tab_id>`: Rename a tab.
*   [x] **Tab Management (Frontend UI):**
    *   [x] Add UI elements for creating, deleting, and renaming tabs.
    *   [x] Implement JS to interact with the corresponding API endpoints and update the UI.
*   [x] **Night Mode / Dark Theme:**
    *   [x] Add switch checkbox in settings menu.
    *   [x] Define CSS styles for .night-mode theme overrides.
    *   [x] Implement JavaScript theme-switching logic and localStorage persistence.
    *   [x] Add comprehensive Playwright E2E test suite.
*   [x] **Dynamic Updates (Backend-driven):**
    *   [x] The backend uses `APScheduler` to automatically fetch feed updates on a regular, configurable interval.
    *   [x] The backend pushes notifications to connected clients using Server-Sent Events (SSE) when updates are complete.
    *   [x] The frontend listens for SSE events and automatically refreshes the UI to display new content in near real-time.
*   [x] Implement "unread" status (if desired):
    *   [x] Add `is_read` flag to `FeedItems` model (default: false).
    *   [x] Add API endpoint `POST /api/items/<item_id>/read` or similar.
    *   [x] Update frontend to mark items visually and call the API (e.g., on click, or mark all visible as read).
    *   [x] Fix middle-click not marking items as read by adding `auxclick` listener.
    *   [x] Update backend to calculate unread counts per feed/tab.
    *   [x] Display unread counts in the UI (widgets, tabs).

## Phase 4: Refinement, Persistence & Deployment

*   [x] **Persistence:** Ensure the database file is stored in a persistent volume mapped into the Podman container. Update `Containerfile` accordingly.
*   [x] **Error Handling:** Improve error handling on both backend (API responses) and frontend (network errors, parsing issues). Show user-friendly error messages.
*   [x] **Configuration:** Allow basic configuration (e.g., feed update interval) via environment variables or a simple config file.
*   [x] **Styling:** Refine CSS to better match the Netvibes look and feel. Make it reasonably responsive.
*   [x] **Empty States:** Handle cases where a feed has no items or a tab has no feeds. Display informative messages.
*   [x] **Optimization:**
    *   [x] Optimize database queries.
    *   [x] Implement backend caching (Redis) with granular invalidation.
    *   [x] Minimize frontend re-renders.
*   [x] **Developer Experience:**
    *   [x] Implement `scripts/dev_manager.sh` for simplified local environment management.
*   [x] **Documentation:**
    *   [x] Write `README.md` covering setup instructions (building/running with Podman), configuration, and basic usage.
    *   [x] Add comments to the code (JSDoc for frontend, Google Style for backend).
*   [x] **Testing:**
    *   [x] Add basic unit tests for backend logic (feed parsing, database interactions).
    *   [x] Add basic unit tests for backend logic (API endpoints).
    *   [x] Consider basic end-to-end tests. (Implemented: Playwright headless Chrome with auto-managed Flask server, PR #520)
*   [x] Finalize `Containerfile` for production readiness (non-root user, proper volume mounts, etc.).

## Backend Security Hardening

*   [x] Validate feed URL schemes (`http:`, `https:`) in `add_feed` and `update_feed_url` endpoints.
*   [x] Strip port from host for SSL SNI `server_hostname` extraction in `SafeHTTPSConnection.connect()`.
*   [x] Filter XML 1.0 invalid control characters in OPML export.
*   [x] Add security unit test suite in `tests/unit/test_security.py`.


## Frontend Security Hardening

*   [x] Implement `sanitizeUrl(url)` helper function permitting only `http:`, `https:`, `/`, and `mailto:` schemes in `frontend/js/utils.js`.
*   [x] Apply `sanitizeUrl` to feed item links and widget title links in `frontend/js/ui.js`.
*   [x] Wrap dynamic path and query parameters (`tabId`, `feedId`, `itemId`, `offset`, `limit`) in `encodeURIComponent()` in `frontend/js/api.js`.
*   [x] Add `rel="noopener noreferrer"` to dynamic OPML export download link in `frontend/js/app.js`.
*   [x] Add unit test coverage for frontend URL sanitization and parameter encoding in `frontend/js/utils.test.js`, `frontend/js/api.test.js`, and `frontend/js/ui.test.js`.

## Code Review Completion

*   [x] **PR #100 Review Comments Addressed:**
  * [x] Fixed backend performance issue in `update_feed_url` function
  * [x] Updated frontend API configuration for production
  * [x] Fixed frontend error handling syntax and UX

## Documentation & Process Improvements

*   [x] Added code review cycle documentation for maintaining PR descriptions across review cycles

## Future Considerations

*   [x] Import/Export OPML feed lists. (Refactored for robustness, SSE progress, and XSS prevention)
*   [x] Hacker News & discussion thread link support with secondary article links.
*   [ ] Widget resizing/reordering (drag and drop).
*   [ ] Different widget view types (e.g., list vs. expanded).
*   [ ] User authentication.
*   [ ] Keyword filtering/highlighting within feeds.
*   [ ] More advanced configuration options per feed.

## Process

*   [x] **2026-08-14: Multi-User Account Support & Admin Panel - PR 1: User Model, Auth Engine & Migration**
  - [x] Implemented `User` model in `backend/models.py` with password hashing (`werkzeug.security`), role checking (`is_admin`), and `Tab.user_id` foreign key.
  - [x] Implemented authentication engine and decorators (`backend/auth.py` with `@login_required`, `@admin_required`, `get_current_user`, `login_user`, `logout_user`).
  - [x] Created authentication blueprint (`backend/blueprints/auth.py`) supporting `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, and `/api/auth/password`.
  - [x] Added Alembic database migration (`backend/migrations/versions/b2c3d4e5f6a7_add_user_model_and_tab_user_id.py`) with automatic default admin seeding and existing tab association.
  - [x] Added unit tests (`tests/unit/test_auth.py`) covering user model, password verification, auth endpoints, and route protection decorators.
  - [x] Validated full test suite: 39/39 Vitest, 202/202 Pytest unit, and 10/10 Playwright E2E tests passing.

*   [x] **2026-08-14: Strict Pull Request Policy & Prohibition of Direct Pushes to `main`**
  - [x] Enacted strict rule in `AGENTS.md` requiring all changes without exception to go through dedicated branches and Pull Requests.
  - [x] Prohibited direct pushes to `main` under any circumstances.

*   [x] **2026-08-14: Canonical Short Feed Names & Single-Line Widget Title Bars**
  - [x] Enforced strict single-line CSS truncation (`white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0;`) and compact header layout in `frontend/style.css` and `frontend/js/ui.js`.
  - [x] Added `feed-widget-title` class and hover tooltip `title` attribute to feed widget headers.
  - [x] Implemented canonical short feed name normalizer and cleaner in `backend/feed_name_utils.py` stripping boilerplate prefixes, suffixes, and taglines (e.g. converting `"GPU News, CPU News, Reviews & PC Hardware Guides"` to `"Wccftech"`, `"www.theregister.com - Articles"` to `"The Register"`, and `"Ars Technica - All content"` to `"Ars Technica"`).
  - [x] Integrated canonical name extraction into feed creation, OPML import, and background metadata updates in `backend/feed_service.py` and `backend/blueprints/feeds.py`.
  - [x] Added comprehensive unit tests in `tests/unit/test_feed_name_utils.py` and `frontend/js/ui.test.js`, and Playwright E2E integration test in `tests/e2e/test_widget_titles.py`.
  - [x] Validated 100% test pass rate across Vitest (39/39), Pytest unit (191/191), and Playwright E2E (10/10).

*   [x] **2026-08-14: Swap Article and Comments Links (Article Primary, Comments Secondary)**
  - [x] Swapped feed item main link to point directly to original article (`item.link`).
  - [x] Renamed secondary link to `comments` pointing to discussion thread (`item.comments_url`).
  - [x] Updated CSS classes and styles (`.item-comments-link`) in light and night modes.
  - [x] Updated Vitest unit tests in `frontend/js/ui.test.js` and Playwright E2E tests in `tests/e2e/test_comments_links.py`.
  - [x] Validated 100% pass rate across Vitest (36/36), Pytest unit (173/173), and Playwright E2E suites.

*   [x] **2026-08-14: Multi-User Accounts Support and Admin Panel (Issue #324 - PR 5: First-Run Onboarding Wizard, Docs & Release)**
  - [x] First-run setup API (`/api/auth/status` and `/api/auth/setup`) in `backend/blueprints/auth.py`.
  - [x] First-run onboarding wizard modal `setup-wizard-modal` in `frontend/index.html`, `frontend/js/ui.js`, `frontend/js/app.js`, `frontend/style.css`.
  - [x] Architectural documentation in `docs/multi-user.md` and feature summary in `README.md`.
  - [x] Unit test suites in `tests/unit/test_setup_wizard.py`, `frontend/js/ui.test.js`, `frontend/js/api.test.js`.
  - [x] Playwright E2E browser test suite in `tests/e2e/test_setup_wizard.py`.
  - [x] Validated 100% test pass rate across Vitest (58/58), Pytest unit (216/216), and Playwright E2E suite (16 passed, 1 skipped).

*   [x] **2026-08-14: Multi-User Accounts Support and Admin Panel (Issue #324 - PR 4: Admin Panel - User Management & Diagnostics)**
  - [x] Admin Blueprint in `backend/blueprints/admin.py` with user CRUD, account safeguards, stats diagnostics, and DB backup.
  - [x] Frontend Admin controller module `frontend/js/admin.js`, modals in `frontend/index.html`, and CSS in `frontend/style.css`.
  - [x] Admin API client integration in `frontend/js/api.js` and lifecycle wiring in `frontend/js/app.js`.
  - [x] Unit test suites in `tests/unit/test_admin.py`, `frontend/js/admin.test.js`, `frontend/js/api.test.js`.
  - [x] Playwright E2E browser test suite in `tests/e2e/test_admin_panel.py`.
  - [x] Validated 100% test pass rate across Vitest (55/55), Pytest unit (214/214), and Playwright E2E suite (15 passed, 1 skipped).

*   [x] **2026-08-14: Multi-User Accounts Support and Admin Panel (Issue #324 - PR 3: Frontend Authentication UI & User State)**
  - [x] Auth API methods and 401 unauthorized interceptor in `frontend/js/api.js`.
  - [x] Header user navigation, dropdown menu, and role badge in `frontend/index.html`, `frontend/js/ui.js`, `frontend/style.css`.
  - [x] Login modal and Change Password modal with client-side validation and responsive/night-mode styling.
  - [x] Session lifecycle initialization and logout state management in `frontend/js/app.js`.
  - [x] Unit test suites in `frontend/js/api.test.js`, `frontend/js/ui.test.js`, and Playwright E2E tests in `tests/e2e/test_auth_ui.py`.
  - [x] Validated 100% test pass rate across Vitest (47/47), Pytest unit (207/207), and Playwright E2E suite (12 passed, 1 skipped).

*   [x] **2026-08-14: Multi-User Accounts Support and Admin Panel (Issue #324 - PR 2: Tenant Scoping, Cache Partitioning & API Isolation)**
  - [x] Database composite unique constraint (`user_id`, `name`) on `Tab`.
  - [x] Protected all tab, feed, item, and OPML routes with `@login_required` and scoped queries to `current_user.id`.
  - [x] User-partitioned cache keys in `backend/cache_utils.py` with user-specific version counters.
  - [x] User-scoped OPML import and export pipelines in `backend/feed_service.py` and `backend/blueprints/opml.py`.
  - [x] Dedicated unit test suite in `tests/unit/test_tenant_isolation.py` and updated client test fixtures.
  - [x] Validated 100% test pass rate across Vitest (39/39) and Pytest unit tests (206/206).

*   [x] **2026-08-14: Multi-User Accounts Support and Admin Panel (Issue #324 - PR 1: Core User Model & Auth Engine)**
  - [x] Implemented `User` model in `backend/models.py` with password hashing and `Tab.user_id` foreign key.
  - [x] Created authentication engine in `backend/auth.py` and API blueprint in `backend/blueprints/auth.py`.
  - [x] Added Alembic database migration seeding legacy tabs into initial administrator.
  - [x] Added comprehensive auth unit test suite in `tests/unit/test_auth.py`.

*   [x] **2026-08-14: Comprehensive Verification of Hacker News Comments Links**
  - [x] Implemented comprehensive Playwright E2E test suite in `tests/e2e/test_comments_links.py` (9/9 E2E tests).
  - [x] Added comprehensive unit test suite across Pytest backend and Vitest frontend:
    - RSS 2.0 real XML parsing for Hacker News and Lobsters feeds (story posts vs. ask/self-posts).
    - Atom link rel variations (`replies`, `discussion`, `comments`).
    - Malformed and unsafe URL filtering (non-string, whitespace, non-http/https schemes).
    - Database update idempotency and upstream omitted-comments preservation.
    - API serialization and pagination comments_url preservation in `FeedItem.to_dict()` and `_get_top_items_for_feeds`.
    - Frontend Vitest suite covering discussion links, secondary article links, URL sanitization, and click/middle-click mark-as-read handlers.
  - [x] Verified 100% test pass rate across Vitest (36/36), Pytest unit (173/173), and Playwright E2E (9/9).

*   [x] **2026-08-14: Hacker News & Feed Comments Thread Link Support**
  - [x] Extended `FeedItem` model and added migration `8e59ae7a1c5b` for `comments_url` field.
  - [x] Implemented feed parser comments extraction and URL structure validation in `backend/feed_service.py` supporting RSS 2.0 `<comments>` and Atom `rel="replies"`.
  - [x] Updated API serializers in `backend/models.py` and `backend/blueprints/tabs.py`.
  - [x] Implemented UI rendering in `frontend/js/ui.js` and `frontend/style.css` to make discussion thread primary/default and provide a secondary `[article]` link with unread status marking on click/middle-click.

*   [x] **2026-08-13: Documentation Overhaul & Automated Release Workflow**
  - [x] Published GitHub Releases for `v0.26` (Valkey standardization) and `v0.27` (Night Mode, WCAG AA contrast, and Dependabot updates).
  - [x] Updated `.github/workflows/release.yml` with `contents: write` permissions and automatic `gh release create` execution upon pushing `v*.*` tags.
  - [x] Updated `README.md`, `TESTING.md`, and `AGENTS.md` to ensure documentation consistency across backend unit tests, Vitest frontend suite, Playwright E2E tests, and release procedures.
  - [x] Validated full test suites across frontend Vitest (23/23), Pytest backend unit tests (160/160), and Playwright E2E tests (3/3).

*   [x] **2026-08-13: Standardize on Valkey instead of Redis**
  - [x] Migrated caching container image and service definitions from Redis to Valkey pinned to latest release tag `docker.io/valkey/valkey:9.1.1` (standard Debian-based image to guarantee GLIBC/tooling compatibility and prevent BusyBox `nc -z` / health check restart issues).
  - [x] Updated Quadlet service configurations (`pod/sheepvibes-valkey.container`, `pod/sheepvibes-valkey.volume`), deployment scripts (`scripts/deploy_pod.sh`, `scripts/dev_manager.sh`), CI workflows (`.github/workflows/run-tests.yml`), and environment variables (`CACHE_VALKEY_URL`, `CACHE_VALKEY_PORT`).
  - [x] Verified full unit and E2E test suites pass with Valkey cache container.

*   [x] **2026-08-12: PR #523 Code Review Resolution & E2E live_server Fix**
  - [x] Implemented safe `localStorage` helper wrappers with try-catch fallback handling in `frontend/js/utils.js` and `frontend/js/app.js`.
  - [x] Fixed `live_server` SQLite in-memory isolation issue in `backend/app.py` and `backend/blueprints/opml.py` with global `SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"uri": True}}` and URI parameter cleaning.
  - [x] Fixed WCAG 2.1 AA color contrast for night mode read items, buttons (`#005a9c`), and focus states in `frontend/style.css`.
  - [x] Added `document.body` guards at top-level module load and ARIA `role="switch"` state sync in `frontend/js/app.js`.
  - [x] Verified 100% pass rate across frontend vitest (23/23) and backend/e2e pytest suite (162/162 passed, 0 skipped).

*   [x] **2026-08-06: Production Feed Refresh Investigation & Fix**
  - [x] Fixed deduplication logic bug in `_process_single_entry` where link matching overwrote items with distinct GUIDs.
  - [x] Increased feed download timeout to 20 seconds (`DEFAULT_FEED_FETCH_TIMEOUT`).
  - [x] Updated deprecated/broken feed URLs for Phoronix, Techno-Science, and NYT World News in `test_feeds.opml` and production database.
  - [x] Rebuilt container image, restarted systemd service, and verified 53/53 feeds successfully refresh in production.

*   [x] **2026-08-05: Playwright E2E Infrastructure (PR #520)**
  - [x] Implemented `live_server` fixture with `start_new_session=True` and `DEVNULL` streams.
  - [x] Added `TEST_BASE_URL` env var detection to bypass local subprocess server when provided.
  - [x] Added unit tests for fixture options in `tests/unit/test_e2e_conftest.py`.

*   [x] **2026-05-15: Kanban cleanup and Jules workflow reset**

  - [x] Rollback `main` to last known-good state (07e67b2).
  - [x] Preserve Dependabot dependency bumps.
  - [x] Close all open PRs bypassing the review loop.
  - [x] Delete all active Jules sessions (253 removed).
  - [x] Cancel stale kanban tasks.
  - [x] Enact `docs/process/jules-pr-workflow.md` with five-gate review loop.
  - [x] Validate full test suite passes at restored state.
*   [x] **2026-08-05: Remove non-portable host volume mount from Quadlet config** (PR #500)
