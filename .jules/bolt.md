## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-08 - Optimized get_tabs unread counts
**Learning:** `Tab.to_dict()` triggered separate SQL queries for unread counts, causing N+1 issues. `Tab` has no direct relationship to `FeedItem`, requiring a join through `Feed`.
**Action:** Use `db.session.query(Feed.tab_id, func.count(FeedItem.id)).join(FeedItem, Feed.id == FeedItem.feed_id)...group_by(Feed.tab_id)` to aggregate counts and pass them to `Tab.to_dict`.
