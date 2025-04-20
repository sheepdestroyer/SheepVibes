# SheepVibes

## Project Overview

SheepVibes is a self-hosted RSS/Atom feed aggregator designed to replicate the core functionality and user experience of Netvibes. The goal is to provide a lightweight, personal dashboard where users can monitor multiple web feeds, organized into customizable topic-based tabs.

Based on the visual layout and functionality of Netvibes, SheepVibes aims to deliver the following features:

1.  **Dashboard Interface:** A central view displaying multiple feed sources simultaneously.
2.  **Grid Layout:** Feeds are presented in distinct rectangular boxes (widgets or modules) arranged in a grid. The layout should be responsive or configurable.
3.  **Feed Widgets:** Each widget represents a single RSS/Atom feed and displays:
    *   The name/title of the feed source.
    *   A list of the latest article titles from the feed.
    *   Timestamps or relative times indicating when each article was published or fetched (e.g., "2:00 PM", "26 min ago", "Apr 2").
    *   Potentially, an indicator for the number of unread items (like the counters "158", "1K+").
    *   Controls for basic widget management (e.g., closing/removing the feed widget, potentially configuration).
4.  **Dynamic Updates:** Feed widgets automatically refresh in the background to fetch and display the latest articles without requiring a full page reload.
5.  **Tabbed Organization:** A tab system at the top allows users to group related feed widgets onto different dashboard pages (tabs). Users should be able to switch between tabs to view different sets of feeds.
6.  **Feed Management:** Functionality to add new RSS/Atom feeds to the dashboard (likely associated with a specific tab) and remove existing ones.
7.  **Self-Hosted & Containerized:** The entire application must run within a Podman container for easy deployment and management.
8.  **Lightweight & Minimal Dependencies:** The technology stack should prioritize simplicity, performance, and minimal external requirements.
9.  **Persistence:** User configuration (added feeds, tab organization, potentially widget layout) must be saved persistently across application restarts.
10. **Clear Documentation:** The project will include documentation covering setup, usage, and development.

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
