## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-13 - Optimized get_tabs endpoint
**Learning:** `Tab.to_dict()` caused N+1 queries by fetching unread counts individually for each tab in `get_tabs`.
**Action:** Implemented a single aggregation query using `GROUP BY` to fetch all unread counts at once, reducing queries from N+1 to 2.
