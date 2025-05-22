# JULES.md - Discrepancies and Observations for SheepVibes

This document lists discrepancies, potential improvements, and observations identified during the review of the SheepVibes project's code, tests, and scripts.

## Status Markers:
*   `[Critical]` - High priority, immediate attention required.
*   `[Major]` - Significant issue, should be addressed soon.
*   `[Minor]` - Small issue or potential improvement.
*   `[Style]` - Code style or best practice inconsistency.
*   `[Naming/Methodology]` - Inconsistency in naming or development approach.

---

### 1. `TODO.md` vs. Backend Polling Endpoint
*   **Description:** The `TODO.md` (Phase 3, "Dynamic Updates (Polling Implementation)") lists "Create a backend endpoint like `GET /api/updates?since=<timestamp>` or per-feed checks" as `[ ]` (not done). However, the overall "Dynamic Updates (Polling Implementation)" is marked `[x]` (done). The current backend (`app.py`) implements a background scheduler (`scheduled_feed_update`) and a manual update endpoint (`POST /api/feeds/<int:feed_id>/update`), but not the specific `GET /api/updates?since=<timestamp>` endpoint.
*   **Status:** `[Minor]` - The broader feature is implemented, but the specific suggested API endpoint is not. This is more a discrepancy in the `TODO.md`'s granularity or a decision to implement the feature differently.

### 2. API Response Consistency
*   **Description:** The `app.py` endpoints `POST /api/items/<int:item_id>/read` and `DELETE /api/feeds/<int:feed_id>` (and `DELETE /api/tabs/<int:tab_id>`) return a 200 OK status with a JSON message. While functional, RESTful API best practices often suggest returning 204 No Content for successful DELETE operations and sometimes for idempotent PUT/POST operations that don't return new resources. The code comments in `app.py` even suggest this.
*   **Status:** `[Style]` - Functional, but could be more aligned with common REST conventions for clearer API semantics.

### 3. Frontend Polling Interval Hardcoding
*   **Description:** The `POLLING_INTERVAL_MS` in `frontend/script.js` is hardcoded to `5 * 60 * 1000` (5 minutes). In contrast, the backend's `UPDATE_INTERVAL_MINUTES` (for the background scheduler) is configurable via an environment variable. This creates a potential for desynchronization between frontend display updates and backend data fetching, or requires manual frontend code changes for configuration.
*   **Status:** `[Minor]` - For better configurability and consistency, the frontend polling interval could ideally be fetched from a backend endpoint or made configurable via a frontend-specific mechanism.

### 4. `backend/test_feed.py` as a Test Script
*   **Description:** The file `backend/test_feed.py` is named like a unit test file (following `test_*.py` convention) but functions more as a standalone utility or manual testing/demonstration script. It imports `app` and `db` directly and runs functions like `test_fetch_feed` and `add_test_feed` when executed. This contrasts with the `pytest`-based automated tests found in `backend/test_app.py` and `backend/test_feed_service.py`.
*   **Status:** `[Naming/Methodology]` - Its role should be clarified. If intended for automated testing, it should be refactored to use `pytest` fixtures and assertions. If it's a utility, its name should reflect that (e.g., `backend/feed_cli_tool.py` or `backend/manual_feed_tester.py`).

### 5. Frontend Error Reporting
*   **Description:** The `fetchData` function in `frontend/script.js` uses `alert()` to display error messages to the user. While simple, `alert()` can be disruptive and block user interaction.
*   **Status:** `[Minor]` - For improved user experience, consider replacing `alert()` with a less intrusive notification system (e.g., a temporary toast message, a dedicated error display area).
