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
