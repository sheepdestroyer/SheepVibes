## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-01-26 - Optimized get_tabs serialization
**Learning:** `Tab.to_dict()` also triggered a separate SQL query for unread counts, causing N+1 issues similar to feeds.
**Action:** Applied the same pattern: pre-calculate unread counts for all tabs using `GROUP BY` and pass them to `to_dict`.
