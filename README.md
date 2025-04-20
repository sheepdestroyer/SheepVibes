# SheepVibes

A simple, self-hosted RSS/Atom feed aggregator inspired by Netvibes, built with Flask and Vanilla JavaScript, designed to run in a Podman container.

## Features

*   Organize feeds into customizable tabs.
*   Add feeds via URL.
*   Delete feeds.
*   Create, rename, and delete tabs.
*   Automatic background fetching of feed updates.
*   Mark items as read.
*   Displays unread counts per feed and per tab.
*   Basic persistence using a SQLite database.

## Running with Podman

1.  **Build the Image:**
    Navigate to the project root directory (where the `Containerfile` is located) and run:
    ```bash
    podman build -t sheepvibes .
    ```

2.  **Create a Persistent Volume (Optional but Recommended):**
    To ensure your database and configuration persist even if the container is removed, create a named volume:
    ```bash
    podman volume create sheepvibes-data
    ```

3.  **Run the Container:**
    *   **With Persistent Volume:**
        ```bash
        podman run -d --name sheepvibes-app \
          -p 5000:5000 \
          -v sheepvibes-data:/app/backend \
          --restart unless-stopped \
          localhost/sheepvibes
        ```
        *   `-d`: Run in detached mode (background).
        *   `--name sheepvibes-app`: Assign a name to the container.
        *   `-p 5000:5000`: Map port 5000 on your host to port 5000 in the container.
        *   `-v sheepvibes-data:/app/backend`: Mount the named volume to the `/app/backend` directory inside the container, where `sheepvibes.db` will be stored.
        *   `--restart unless-stopped`: Automatically restart the container unless manually stopped.

    *   **Without Persistent Volume (Data lost if container is removed):**
        ```bash
        podman run -d --name sheepvibes-app -p 5000:5000 localhost/sheepvibes
        ```

4.  **Access SheepVibes:**
    Open your web browser and navigate to `http://localhost:5000`.

## Configuration (Environment Variables)

You can configure the application by passing environment variables during the `podman run` command using the `-e` flag:

*   `DATABASE_PATH`: The full path *inside the container* where the SQLite database file should be stored. Defaults to `/app/backend/sheepvibes.db`. If using the recommended volume mount, this path is within the volume.
    *   Example: `-e DATABASE_PATH=/app/backend/my_custom_name.db`
*   `UPDATE_INTERVAL_MINUTES`: The interval (in minutes) at which the application checks feeds for updates. Defaults to `15`.
    *   Example: `-e UPDATE_INTERVAL_MINUTES=30`

**Example running with custom configuration:**

```bash
podman run -d --name sheepvibes-app \
  -p 5000:5000 \
  -v sheepvibes-data:/app/backend \
  -e UPDATE_INTERVAL_MINUTES=60 \
  --restart unless-stopped \
  localhost/sheepvibes
```

## Development

(TODO: Add instructions for setting up a local development environment without Podman)

## License

(TODO: Add License - e.g., MIT)

## Current Implementation Status

### Backend API (Phase 0 & 1 Complete)

The backend of SheepVibes is implemented using Flask with SQLAlchemy for database operations. It consists of:

- **Database Models**: Tab, Feed, and FeedItem models defined using SQLAlchemy.
- **Feed Service**: A module for fetching and parsing RSS/Atom feeds using feedparser, with error handling for various feed formats.
- **Scheduled Updates**: Background job scheduler (APScheduler) to periodically check feeds for updates.
- **API Endpoints**:
  - `GET /api/tabs`: List all tabs
  - `GET /api/tabs/<tab_id>/feeds`: List feeds for a specific tab
  - `GET /api/feeds/<feed_id>/items`: List recent items for a specific feed (with pagination)
  - `POST /api/feeds/<feed_id>/update`: Manually trigger an update for a specific feed

### Testing

You can test the feed fetching and processing functionality using the provided test script:

```bash
# Test with default feeds
cd backend && source venv/bin/activate
python test_feed.py

# Test with a specific feed URL (arstechnica)
cd backend && source venv/bin/activate
python test_feed.py https://feeds.arstechnica.com/arstechnica/index
```

### Environment Variables

The application supports the following environment variables:

- `DATABASE_PATH`: Path to the SQLite database file (default: `backend/sheepvibes.db`)
- `UPDATE_INTERVAL_MINUTES`: Interval in minutes for feed updates (default: 15)

### Next Steps

- Frontend implementation (Phase 2)
- User interactivity features (Phase 3)
- Refinement and deployment enhancements (Phase 4)
