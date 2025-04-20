# SheepVibes - Implementation Plan (TODO)

This document outlines the steps to build the SheepVibes RSS aggregator.

## Phase 0: Project Setup & Core Backend

*   [ ] Initialize project structure (directories for backend, frontend, docs, etc.).
*   [ ] Set up Python virtual environment (`venv`).
*   [ ] Install initial Python dependencies (`Flask`, `feedparser`, `APScheduler`, `SQLAlchemy`).
*   [ ] Create a basic Flask application (`app.py`).
*   [ ] Define database schema/models (using `SQLAlchemy`):
    *   `Tabs` (id, name, order)
    *   `Feeds` (id, tab_id, name, url, last_updated_time)
    *   `FeedItems` (id, feed_id, title, link, published_time, fetched_time, is_read)
*   [ ] Implement basic database initialization logic.
*   [ ] Create initial `Containerfile` for Podman (Python base image, install dependencies, expose port).
*   [ ] Set up basic logging.
*   [ ] Add `.gitignore`.

## Phase 1: Feed Fetching & Processing

*   [ ] Create a service/module for fetching and parsing RSS/Atom feeds using `feedparser`.
    *   Handle potential errors during fetching/parsing (timeouts, invalid URLs, bad feed formats).
*   [ ] Implement logic to store/update feed details and new items in the database.
    *   Avoid duplicating existing items (check GUIDs or links).
    *   Update `last_updated_time` for the feed.
*   [ ] Set up `APScheduler` as a background task within the Flask app (or as a separate process if preferred).
    *   Schedule a recurring job to fetch updates for all configured feeds.
    *   Make the interval configurable (e.g., every 15 minutes).
*   [ ] Implement initial backend API endpoints (using Flask Blueprints):
    *   `GET /api/tabs`: List all tabs.
    *   `GET /api/tabs/<tab_id>/feeds`: List feeds for a specific tab.
    *   `GET /api/feeds/<feed_id>/items`: List recent items for a specific feed (with limit/pagination).

## Phase 2: Basic Frontend Structure & Display

*   [ ] Create basic HTML structure (`index.html`).
    *   Include placeholders for tabs.
    *   Include a container for the feed widget grid.
*   [ ] Create basic CSS (`style.css`) for layout:
    *   Style the tab bar.
    *   Implement a CSS Grid or Flexbox layout for the feed widgets.
    *   Style individual feed widgets (borders, padding, header, item list).
*   [ ] Write Vanilla JavaScript (`script.js`) to:
    *   Fetch tabs from `/api/tabs` on page load and render them.
    *   Fetch feeds for the initially active tab (`/api/tabs/<tab_id>/feeds`).
    *   For each feed, fetch its items (`/api/feeds/<feed_id>/items`).
    *   Render the feed widgets dynamically in the grid, populating them with titles and timestamps.
    *   Handle switching between tabs (fetch and render feeds for the selected tab).

## Phase 3: Interactivity & Core Features

*   [ ] **Feed Management (Backend API):**
    *   `POST /api/feeds`: Add a new feed (URL, optionally associate with a tab). Backend should fetch initial data upon adding.
    *   `DELETE /api/feeds/<feed_id>`: Remove a feed.
    *   `PUT /api/feeds/<feed_id>`: Update feed properties (e.g., move to different tab - maybe later).
*   [ ] **Feed Management (Frontend UI):**
    *   Add a "+" button or form to input a feed URL.
    *   Implement JS to call the `POST /api/feeds` endpoint.
    *   Add a "close" (X) button to each feed widget.
    *   Implement JS for the close button to call `DELETE /api/feeds/<feed_id>` and remove the widget from the DOM.
*   [ ] **Tab Management (Backend API):**
    *   `POST /api/tabs`: Create a new tab.
    *   `DELETE /api/tabs/<tab_id>`: Delete a tab (handle associated feeds - delete them or move to default?).
    *   `PUT /api/tabs/<tab_id>`: Rename a tab.
*   [ ] **Tab Management (Frontend UI):**
    *   Add UI elements for creating, deleting, and renaming tabs.
    *   Implement JS to interact with the corresponding API endpoints and update the UI.
*   [ ] **Dynamic Updates (Polling Implementation):**
    *   Create a backend endpoint like `GET /api/updates?since=<timestamp>` or per-feed checks. (Simpler: just re-fetch items for visible feeds periodically).
    *   Implement frontend JS using `setInterval` to periodically re-fetch items for currently displayed feeds and update the DOM if new items are found.
    *   *Alternative/Upgrade:* Implement Server-Sent Events (SSE) for more efficient updates pushed from the server.
*   [ ] Implement "unread" status (if desired):
    *   Add `is_read` flag to `FeedItems` model (default: false).
    *   Add API endpoint `POST /api/items/<item_id>/read` or similar.
    *   Update frontend to mark items visually and call the API (e.g., on click, or mark all visible as read).
    *   Update backend to calculate unread counts per feed/tab.
    *   Display unread counts in the UI (widgets, tabs).

## Phase 4: Refinement, Persistence & Deployment

*   [ ] **Persistence:** Ensure the database file is stored in a persistent volume mapped into the Podman container. Update `Containerfile` accordingly.
*   [ ] **Error Handling:** Improve error handling on both backend (API responses) and frontend (network errors, parsing issues). Show user-friendly error messages.
*   [ ] **Configuration:** Allow basic configuration (e.g., feed update interval) via environment variables or a simple config file.
*   [ ] **Styling:** Refine CSS to better match the Netvibes look and feel. Make it reasonably responsive.
*   [ ] **Empty States:** Handle cases where a feed has no items or a tab has no feeds. Display informative messages.
*   [ ] **Optimization:**
    *   Optimize database queries.
    *   Consider backend caching for frequently accessed data if needed.
    *   Minimize frontend re-renders.
*   [ ] **Documentation:**
    *   Write `README.md` covering setup instructions (building/running with Podman), configuration, and basic usage.
    *   Add comments to the code.
*   [ ] **Testing:**
    *   Add basic unit tests for backend logic (feed parsing, database interactions).
    *   Consider basic end-to-end tests.
*   [ ] Finalize `Containerfile` for production readiness (non-root user, proper volume mounts, etc.).

## Future Considerations

*   [ ] Widget resizing/reordering (drag and drop).
*   [ ] Import/Export OPML feed lists.
*   [ ] Different widget view types (e.g., list vs. expanded).
*   [ ] User authentication.
*   [ ] Keyword filtering/highlighting within feeds.
*   [ ] More advanced configuration options per feed.
