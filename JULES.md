# Project Discrepancies & Review (JULES)

This document lists discrepancies found during the project review, comparing documentation, code, tests, and scripts.

## Key:
*   `[ ]` - To Do / Needs Addressing
*   `[~]` - Under Review / Minor Issue / Observation
*   `[x]` - Resolved / Addressed
*   `[!]` - Important / Potential Bug

---

## Discrepancies List

1.  **`[ ]` [Doc/Script Mismatch] README vs. Local Scripts Image Source:**
    *   **Description**: `README.md` `podman run` examples use the public image `ghcr.io/sheepdestroyer/sheepvibes:latest`. Scripts like `manage_container.sh` and `rebuild_container.sh` use the locally built image name `sheepvibes-app`.
    *   **Files**: `README.md`, `scripts/manage_container.sh`, `scripts/rebuild_container.sh`.
    *   **Impact**: Minor confusion for users switching between following README for pre-built image and using scripts for local development.
    *   **Suggestion**: Clarify in `README.md` that development scripts use a locally built image named `sheepvibes-app`.

2.  **`[ ]` [Doc/Script Mismatch] README vs. `manage_container.sh` Port Mapping:**
    *   **Description**: `README.md` `podman run` example maps to `127.0.0.1:5000` (local access only by default). The `manage_container.sh` script maps to host port `5000` without specifying an IP, which typically means `0.0.0.0:5000` (accessible externally).
    *   **Files**: `README.md`, `scripts/manage_container.sh`.
    *   **Impact**: Different default accessibility when using README command vs. script.
    *   **Suggestion**: Align the script's default. README already mentions how to change for external listening.

3.  **`[~]` [Code/Feature] Unused API Endpoint:**
    *   **Description**: The backend API endpoint `POST /api/feeds/<feed_id>/update` (for manual feed refresh) defined in `app.py` is not used by the frontend (`script.js`).
    *   **Files**: `backend/app.py`, `frontend/script.js`.
    *   **Impact**: Dead code/feature if not intended for other clients. If intended for UI, it's missing.
    *   **Suggestion**: Either implement a UI element to trigger this or remove the endpoint if it's not planned for use.

4.  **`[~]` [Code/Robustness] Frontend Feed Prepend Heuristic:**
    *   **Description**: In `frontend/script.js`, the `renderFeedWidget` function uses a heuristic `const prependWidget = document.getElementById('add-feed-button').disabled;` to decide whether to prepend a newly added feed widget. This relies on the "Add Feed" button's disabled state during the operation.
    *   **Files**: `frontend/script.js`.
    *   **Impact**: Potentially fragile if the button's disabled state logic changes or is used for other purposes.
    *   **Suggestion**: Consider passing an explicit parameter to `renderFeedWidget` if the prepend/append behavior needs to be more robustly controlled.

5.  **`[ ]` [Test Coverage] Missing Tests for Manual Feed Update API:**
    *   **Description**: `backend/test_app.py` does not include tests for the `POST /api/feeds/<feed_id>/update` endpoint.
    *   **Files**: `backend/test_app.py`, `backend/app.py`.
    *   **Impact**: Untested API endpoint.
    *   **Suggestion**: Add tests for this endpoint.

8.  **`[ ]` [Test Coverage] Missing Tests for Frontend Serving Routes:**
    *   **Description**: `backend/test_app.py` does not include tests for the routes that serve frontend files (`/` and `<path:filename>`).
    *   **Files**: `backend/test_app.py`, `backend/app.py`.
    *   **Impact**: Untested core functionality (serving the application itself).
    *   **Suggestion**: Add basic tests to ensure these routes return expected content (e.g., `index.html`, status codes).

9.  **`[ ]` [Test Coverage] Missing Unit Tests for `feed_service` Functions:**
    *   **Description**: The functions `fetch_and_update_feed` and `update_all_feeds` in `backend/feed_service.py` are not unit tested. Placeholders for these tests are noted in `backend/test_feed_service.py`.
    *   **Files**: `backend/feed_service.py`, `backend/test_feed_service.py`.
    *   **Impact**: Core feed updating logic lacks unit test coverage.
    *   **Suggestion**: Implement the planned unit tests for these functions.

10.  **`[~]` [Clarity/Doc] Purpose of `test_feed.py`:**
    *   **Description**: The file `backend/test_feed.py` is a script for manual/integration testing rather than an automated unit test file integrated with `pytest`.
    *   **Files**: `backend/test_feed.py`.
    *   **Impact**: Its role in the testing strategy might be unclear.
    *   **Suggestion**: Add a comment at the top of `test_feed.py` or in `README.md` clarifying its purpose as a developer utility for manual testing of feed fetching and processing.
