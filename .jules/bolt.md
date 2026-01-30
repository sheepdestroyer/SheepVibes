## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-01-30 - N+1 Query in Tab Serialization
**Learning:** `Tab.to_dict` was executing a separate COUNT query for unread items, causing N+1 queries when fetching the tab list.
**Action:** Always inspect model `to_dict` methods for hidden queries and use pre-calculation + injection (passing `unread_count`) to optimize list endpoints.
