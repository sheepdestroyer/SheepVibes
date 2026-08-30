## 2026-08-30

- **Fix(logging): Preserve host logging handlers while routing application severities by stream (PR #542)**
  - Scoped the application logging setup to its own handler class instead of clearing unrelated root handlers, preserving Gunicorn, test-capture, and host integrations.
  - Restored the root logging configuration in the stream-routing test and added regression coverage for existing handler preservation.
  - Documented stream routing as a container-runtime/systemd convention rather than asserting a universal journald priority mapping.
  - **Verification:** Full backend unit suite passes (219/219), Playwright E2E passes (16 passed, 1 skipped), and full frontend Vitest suite passes (58/58).

## 2026-08-14

- **Feat(auth): First-Run Onboarding Wizard, Documentation & Release (Issue #324 - PR 5)**
  - **First-Run Setup Backend API (`backend/blueprints/auth.py`)**: Added `GET /api/auth/status` (reporting `setup_required`, `authenticated`, and active session user) and `POST /api/auth/setup` (onboarding endpoint to bootstrap the master administrator account and initial tab, permanently rejecting subsequent invocations with 403 Forbidden).
  - **Interactive Onboarding UI (`frontend/index.html`, `frontend/js/ui.js`, `frontend/js/app.js`, `frontend/style.css`)**: Implemented first-run setup wizard modal with branding, input validation, confirmation matching, automatic administrator authentication, and seamless transition to dashboard.
  - **Comprehensive Multi-User Documentation (`docs/multi-user.md`, `README.md`)**: Authored detailed architectural documentation covering multi-tenancy, partitioned caching, RBAC, first-run wizard, Admin Panel features, SQLite snapshot backups, and production Quadlet/Podman deployment configurations.
  - **Unit & Playwright E2E Test Suites (`tests/unit/test_setup_wizard.py`, `frontend/js/ui.test.js`, `frontend/js/api.test.js`, `tests/e2e/test_setup_wizard.py`)**: Added test coverage for setup status checks, master admin bootstrap, validation errors, duplicate setup prevention, and full browser onboarding flow.
  - **Verification**: 100% test pass rate across Vitest (58/58), Pytest unit tests (216/216), and Playwright E2E suite (16 passed, 1 skipped).

- **Feat(admin): Admin Panel, User Management & System Diagnostics (Issue #324 - PR 4)**
  - **Admin Blueprint & Endpoints (`backend/blueprints/admin.py`, `backend/app.py`)**: Implemented `@admin_required` protected endpoints including `/api/admin/users` (list, create), `/api/admin/users/<id>` (update status/role/email/password, delete with cascade), `/api/admin/system/stats` (users/tabs/feeds/items counts, DB size, cache engine health), and `/api/admin/backup` (point-in-time snapshot download).
  - **Account Safeguards (`backend/blueprints/admin.py`)**: Added security guards preventing administrators from self-deactivating, self-demoting, or self-deleting their own active accounts.
  - **Frontend Admin Controller & Modals (`frontend/js/admin.js`, `frontend/index.html`, `frontend/style.css`)**: Built Administration Panel modal with tabbed views for User Management (table with badges, Add User dialog, Edit User dialog, status toggles) and System Diagnostics (metric cards, point-in-time database snapshot download).
  - **Frontend API & Lifecycle Integration (`frontend/js/api.js`, `frontend/js/app.js`)**: Added admin client API methods and integrated Admin Panel trigger into the user account dropdown for administrator accounts.
  - **Unit & Playwright E2E Test Suites (`tests/unit/test_admin.py`, `frontend/js/admin.test.js`, `frontend/js/api.test.js`, `tests/e2e/test_admin_panel.py`)**: Added comprehensive Pytest backend tests (privilege verification, validation, cascading, self-guards, diagnostics, DB backups), Vitest frontend unit tests, and Playwright browser tests.
  - **Verification**: 100% test pass rate across Vitest (55/55), Pytest unit tests (214/214), and Playwright E2E suite (15 passed, 1 skipped).

- **Feat(auth): Frontend Authentication UI, User State & Modals (Issue #324 - PR 3)**
  - **Auth API & Interceptor (`frontend/js/api.js`)**: Added `api.login()`, `api.logout()`, `api.getCurrentUser()`, `api.changePassword()`, and an automatic HTTP 401 unauthorized interceptor (`setUnauthorizedHandler`) that resets frontend user state and opens the login modal when an unauthorized request occurs.
  - **User Navigation & Dropdown Menu (`frontend/index.html`, `frontend/js/ui.js`, `frontend/style.css`)**: Implemented header user control displaying the active username, user role badge (User / Admin), "Change Password" modal trigger, "Admin Panel" navigation button (for administrators), and "Log Out" action.
  - **Authentication Modals & Client-Side Validation (`frontend/index.html`, `frontend/js/ui.js`, `frontend/style.css`)**: Built accessible login modal and change password modal with real-time error banner rendering, minimum password length checks (8+ characters), and confirmation matching.
  - **Session Lifecycle Management (`frontend/js/app.js`)**: Integrated automated session validation on page load (`checkAuthAndInitialize`), rendering protected feeds/tabs only upon successful authentication and clearing session state upon logout or session expiration.
  - **Unit & Playwright E2E Test Suite (`frontend/js/api.test.js`, `frontend/js/ui.test.js`, `tests/e2e/test_auth_ui.py`, `tests/e2e/conftest.py`)**: Added unit test coverage for auth endpoints and modal lifecycle, plus Playwright E2E browser tests validating unauthenticated prompts, login error handling, successful authentication, password change dialogs, and logout workflows.
  - **Verification**: 100% test pass rate across Vitest (47/47), Pytest unit tests (207/207), and Playwright E2E suite (12 passed, 1 skipped).

- **Feat(auth): Tenant Scoping, Cache Partitioning & API Isolation (Issue #324 - PR 2)**
  - **Database Composite Uniqueness (`backend/models.py`)**: Replaced global `Tab.name` unique constraint with composite `UniqueConstraint("user_id", "name", name="uq_tabs_user_id_name")`, allowing distinct users to organize tabs with identical names (e.g., "Tech", "News") while enforcing per-account uniqueness.
  - **Route Protection & User Scoping (`backend/blueprints/tabs.py`, `backend/blueprints/feeds.py`, `backend/blueprints/opml.py`)**: Applied `@login_required` to all tab, feed, item, and OPML routes. Scoped all queries (`Tab`, `Feed`, `FeedItem`) to `user_id == current_user.id` to prevent cross-tenant enumeration and unauthorized access.
  - **Multi-Tenant Cache Partitioning (`backend/cache_utils.py`)**: Partitioned cache keys by user ID (`view/user/{user_id}/tabs/v{version}` and `view/user/{user_id}/tab/{tab_id}/...`) and updated cache invalidators to increment user-specific version keys, preventing cross-user cache collisions or data leakage.
  - **Multi-Tenant OPML Support (`backend/feed_service.py`, `backend/blueprints/opml.py`)**: Updated OPML import and export pipelines to respect user boundaries, creating tabs and feeds under the authenticated user's ID.
  - **Unit Test Suite (`tests/unit/test_tenant_isolation.py`, `tests/conftest.py`)**: Added dedicated multi-tenant isolation unit tests verifying tab and feed isolation, 404 enforcement on foreign resource access, per-user OPML import/export isolation, and partitioned cache keys.
  - **Verification**: 100% test pass rate across Vitest (39/39) and Pytest unit tests (206/206).

- **Feat(auth): User Model, Authentication Engine & Database Migration (Issue #324 - PR 1)**
  - **User Data Model (`backend/models.py`)**: Added `User` model with secure password hashing (`werkzeug.security`), role checking (`is_admin`), timestamps, and linked `Tab.user_id` foreign key (`CASCADE` deletion).
  - **Authentication Engine & Decorators (`backend/auth.py`)**: Built session-based authentication helpers (`get_current_user`, `login_user`, `logout_user`) and route protection decorators (`@login_required`, `@admin_required`).
  - **Auth Blueprint & Endpoints (`backend/blueprints/auth.py`, `backend/app.py`)**: Exposed `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, and `/api/auth/password` with HTTPOnly/SameSite session cookies and configurable lifetime.
  - **Database Migration (`backend/migrations/versions/b2c3d4e5f6a7_add_user_model_and_tab_user_id.py`)**: Created Alembic migration adding `users` table, `tabs.user_id` column, and automated seeding of legacy tabs into a default initial administrator account.
  - **Unit Test Suite (`tests/unit/test_auth.py`)**: Added 8 comprehensive test cases covering user serialization, password hashing, authentication failure modes, session lifecycle, password updates, and route decorator enforcement.
  - **Verification**: 100% test pass rate across Vitest (39/39), Pytest unit tests (202/202), and Playwright E2E suite (10/10).

- **Docs & Governance: Enact Strict Pull Request Policy & Prohibition of Direct Pushes to `main`**
  - **Rule Definition (`AGENTS.md`)**: Enacted strict policy that direct pushes to `main` are prohibited under all circumstances. Every change (features, bug fixes, operational scripts, database migrations, configuration, and documentation) must be made on a dedicated branch and merged via Pull Request.

- **Feat: Canonical Short Feed Names & Single-Line Widget Title Bars**
  - **Single-Line Truncation & Compact Title Bar (`frontend/style.css`, `frontend/js/ui.js`)**: Enforced strict single-line CSS truncation (`white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0;`) on widget title links and spans, added `.feed-widget-title` class and hover tooltip `title` attribute, and adjusted button vertical margins so widget title bars maintain a compact ~36px height while keeping 44px touch targets.
  - **Canonical Short Name Extraction (`backend/feed_name_utils.py`)**: Added `derive_canonical_feed_name` to clean verbose RSS channel `<title>` tags, stripping boilerplate suffixes (`- Articles`, `- News`, `| Homepage`, `:: RSS Feed`), boilerplate prefixes (`Latest from...`), domain artifacts (`www.theregister.com - Articles` → `The Register`), and pure marketing taglines (`GPU News, CPU News, Reviews & PC Hardware Guides` → `Wccftech`).
  - **Backend Metadata, Migration & OPML Integration (`backend/feed_service.py`, `backend/blueprints/feeds.py`, `backend/migrations/versions/a1b2c3d4e5f6_canonicalize_existing_feed_names.py`)**: Added Alembic data migration to automatically canonicalize existing database feed names on startup, and integrated canonical name derivation on initial feed addition, OPML outline import, and background refresh cycles (`_update_feed_metadata`).
  - **Static Asset Caching & Deployment (`backend/app.py`, `pod/sheepvibes-app.container`, `scripts/deploy_pod.sh`)**: Added `Cache-Control: no-cache, must-revalidate` header to static assets, configured `Pull=always` and `AutoUpdate=registry` in Podman Quadlet, and automated fresh image pull on deployment.
  - **Unit & E2E Test Suite (`tests/unit/test_feed_name_utils.py`, `frontend/js/ui.test.js`, `tests/e2e/test_widget_titles.py`)**: Added comprehensive unit tests covering domain normalization, boilerplate removal, HTML unescaping, DOM tooltip rendering, and Playwright E2E integration tests for single-line widget layout and tooltip attributes.
  - **Verification**: 100% test pass rate across Vitest (39/39), Pytest unit tests (194/194), and Playwright E2E suite (10/10).

- **Feat(frontend): Swap Article and Comments Links (Article as Primary, Comments as Secondary)**
  - **Primary & Secondary Link Swap (`frontend/js/ui.js`)**: Updated `createFeedItemElement` so the main item title link opens the original article (`item.link`) directly, and when a discussion thread URL is available (`comments_url` differs from `link`), an inline secondary link labeled `comments` opens the discussion thread.
  - **CSS Styling & Accessibility (`frontend/style.css`)**: Styled `.item-comments-link` with WCAG AA compliant contrast colors in light mode (`#005a9c`) and night mode (`#58a6ff`), hover underline states, and ARIA labels (`aria-label="Open discussion thread: {title}"`).
  - **Test Suite Updates (`frontend/js/ui.test.js`, `tests/e2e/test_comments_links.py`)**: Updated Vitest unit suite and Playwright E2E integration suite to validate primary article links, secondary `comments` links, click and middle-click (`auxclick`) mark-as-read handlers, badge decrements, and light/night mode themes.
  - **Verification**: 100% test pass rate across Vitest (36/36), Pytest unit tests (173/173), and Playwright E2E suite (8 passed, 1 skipped).

- **Test(e2e): Comprehensive Playwright E2E Test Suite for Feed Comments Links**
  - **Comprehensive E2E Coverage (`tests/e2e/test_comments_links.py`)**: Added full browser end-to-end integration tests using Playwright Chromium and `live_server` subprocess.
  - **DOM & Attribute Validation**: Verified rendered discussion thread primary links, secondary `[article]` links, attribute presence/absence (`target="_blank"`, `rel="noopener noreferrer"`, `title`, `aria-label`), suppression of `[article]` for Ask HN (`comments_url == link`), and fallback for feeds without comments.
  - **User Interaction & Read State**: Validated primary link click, secondary `[article]` link click, and middle-click (`auxclick`) triggering item read status (`li.read`), unread badge decrement, duplicate click prevention, and complete badge removal on zero count.
  - **Accessibility & Night Mode Themes**: Validated ARIA semantics, title tooltips, and WCAG AA contrast colors in light (`#005a9c`) and night (`#58a6ff`) modes.
  - **Verification**: 100% test pass rate across Vitest (25/25), Pytest unit tests (166/166), and Playwright E2E suite (9/9).

- **Feat: Hacker News & Feed Comments Thread Link Support**
  - **Backend Data Model & Extraction**: Added `comments_url` column to `FeedItem` model, database migration (`8e59ae7a1c5b`), and feed parsing support in `backend/feed_service.py` to extract and validate `<comments>` tags (RSS 2.0) and `rel="replies"` links (Atom).
  - **API Serialization**: Updated `FeedItem.to_dict()` and `_get_top_items_for_feeds` in `backend/blueprints/tabs.py` to return `comments_url`.
  - **Frontend UI & Accessibility**: When comments thread URL is present and differs from article link, the primary item title link opens the discussion thread (default/primary), and a secondary `[article]` link opens the original article. Added full click and middle-click (`auxclick`) mark-as-read handlers, URL sanitization, and WCAG AA contrast styling in light and night modes.
  - **Testing**: Added comprehensive unit tests in `tests/unit/test_feed.py`, `tests/unit/test_app.py`, and `frontend/js/ui.test.js` covering real-world Hacker News & Lobsters RSS XML parsing, Atom `replies`/`discussion`/`comments` links, malformed URL rejection, DB update idempotency, API serialization/pagination, and frontend click/middle-click mark-as-read interactions. Verified 100% test pass rate across Vitest (36/36), Pytest unit tests (173/173), and Playwright E2E suite (3/3).

## 2026-08-13

- **Docs & Release Automation: GitHub Release Automation & Documentation Consistency**
  - **Release Workflow Automation**: Updated `.github/workflows/release.yml` with `contents: write` permissions and added an automated step to create/update GitHub Releases with auto-generated release notes upon pushing `v*.*` tags.
  - **GitHub Releases Backfill**: Published official GitHub Releases for `v0.26` (Valkey standardization) and `v0.27` (Night Mode, WCAG AA compliance, and Dependabot bumps).
  - **Documentation Alignment**: Synchronized `README.md`, `TESTING.md`, `AGENTS.md`, and `TODO.md` with current project architecture (Flask Blueprints, ES6 JS modules, Valkey 9.1.1, Vitest frontend tests, and Playwright E2E suites).

- **Infrastructure: Standardized caching on Valkey (docker.io/valkey/valkey:9.1.1)**
  - **Container & Service Migration**: Replaced Redis container definitions with Valkey pinned to standard release tag `docker.io/valkey/valkey:9.1.1` (Debian-based base image to prevent BusyBox syntax/probe issues and ensure GLIBC tool compatibility). Updated Quadlet files (`pod/sheepvibes-valkey.container`, `pod/sheepvibes-valkey.volume`), deployment scripts (`scripts/deploy_pod.sh`, `scripts/dev_manager.sh`, `scripts/run_dev.sh`), and GitHub Actions workflow (`.github/workflows/run-tests.yml`) to use `valkey` and `valkey-cli ping`.
  - **Backend & Environment Variables**: Added support for `CACHE_VALKEY_URL` (with fallback to `CACHE_REDIS_URL`) in `backend/app.py` and `CACHE_VALKEY_PORT` in unit/e2e test suites.
  - **Testing**: Added unit test `test_valkey_cache_config_precedence` in `tests/unit/test_app.py`. Verified 100% test pass rate across Vitest (23/23) and Pytest (160 unit tests, E2E suite).

## 2026-08-12

- **Refactor & Fix (PR #523): Night Mode code review resolution & E2E Database Initialization**
  - **Backend & SQLite Safety**: Configured global `SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"uri": True}}` in `backend/app.py` for both testing and production environments. Updated lock path resolution in `backend/app.py` and `_get_autosave_directory()` in `backend/blueprints/opml.py` to correctly identify and strip `file:` URI prefixes and query parameters for SQLite memory databases. Scoped `db.create_all()` execution to application startup (`__main__`).
  - **Frontend & DOM Safety**: Added explicit `document.body` guards at top-level module load and null checks for dropdown elements in `frontend/js/app.js`. Added `aria-checked` state synchronization for `role="switch"`.
  - **UI Contrast & Focus**: Fixed button contrast ratios (`#005a9c`, > 4.5:1) for WCAG 2.1 AA compliance and added `:focus-visible` opacity styling for feed action buttons in `frontend/style.css`.
  - **E2E & Test Quality**: Updated `open_settings_menu` in `tests/e2e/test_infinite_scroll.py` to use natural user click interactions (`page.click('#settings-button')`). Verified 100% test pass rate across Vitest (23/23) and Pytest (162/162).

## 2026-08-11

- **Feat: Night Mode / Dark Theme**
  - **Switch in Settings**: Added a "Night Mode" checkbox under settings.
  - **Theme Styles (.night-mode)**: Wrote extensive CSS overrides for light colors, headers, tabs, settings dropdown, widgets, progress bar, and modal dialogues to render elegant dark interfaces.
  - **Theme Switching & Persistence**: Implemented a JS theme-switcher that updates DOM classes on check/uncheck and persists user state across session reloads via `localStorage`.
  - **E2E Testing**: Added automated Playwright E2E tests for verification of toggling behavior and state persistence in `tests/e2e/test_night_mode.py`.
  - **Fix**: Resolved a pre-existing syntax error/extra brace in `frontend/js/utils.js` within the `throttle` helper, allowing frontend modules to load successfully.

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
