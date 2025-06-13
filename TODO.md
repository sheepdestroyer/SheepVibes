# SheepVibes - Implementation Plan (TODO)

This document outlines the steps to build the SheepVibes RSS aggregator.

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
    *   [ ] `PUT /api/feeds/<feed_id>`: Update feed properties (e.g., move to different tab - maybe later).
*   [x] **Feed Management (Frontend UI):**
    *   [x] Add a "+" button or form to input a feed URL.
    *   [x] Implement JS to call the `POST /api/feeds` endpoint.
    *   [x] Add a "close" (X) button to each feed widget.
    *   [x] Implement JS for the close button to call `DELETE /api/feeds/<feed_id>` and remove the widget from the DOM.
*   [x] **Tab Management (Backend API):**
    *   [x] `POST /api/tabs`: Create a new tab.
    *   [x] `DELETE /api/tabs/<tab_id>`: Delete a tab (handle associated feeds - delete them or move to default?).
    *   [x] `PUT /api/tabs/<tab_id>`: Rename a tab.
*   [x] **Tab Management (Frontend UI):**
    *   [x] Add UI elements for creating, deleting, and renaming tabs.
    *   [x] Implement JS to interact with the corresponding API endpoints and update the UI.
*   [x] **Dynamic Updates (Backend-driven):**
    *   [x] The backend uses `APScheduler` to automatically fetch feed updates on a regular, configurable interval.
    *   [x] The backend pushes notifications to connected clients using Server-Sent Events (SSE) when updates are complete.
    *   [x] The frontend listens for SSE events and automatically refreshes the UI to display new content in near real-time.
*   [x] Implement "unread" status (if desired):
    *   [x] Add `is_read` flag to `FeedItems` model (default: false).
    *   [x] Add API endpoint `POST /api/items/<item_id>/read` or similar.
    *   [x] Update frontend to mark items visually and call the API (e.g., on click, or mark all visible as read).
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
    *   [ ] Consider backend caching for frequently accessed data if needed. (Deferred)
    *   [x] Minimize frontend re-renders.
*   [x] **Documentation:**
    *   [x] Write `README.md` covering setup instructions (building/running with Podman), configuration, and basic usage.
    *   [x] Add comments to the code.
*   [x] **Testing:**
    *   [x] Add basic unit tests for backend logic (feed parsing, database interactions).
    *   [x] Add basic unit tests for backend logic (API endpoints).
    *   [ ] Consider basic end-to-end tests. (Deferred)
*   [x] Finalize `Containerfile` for production readiness (non-root user, proper volume mounts, etc.).

## Future Considerations

*   [ ] Widget resizing/reordering (drag and drop).
*   [ ] Import/Export OPML feed lists.
*   [ ] Different widget view types (e.g., list vs. expanded).
*   [ ] User authentication.
*   [ ] Keyword filtering/highlighting within feeds.
*   [ ] More advanced configuration options per feed.
