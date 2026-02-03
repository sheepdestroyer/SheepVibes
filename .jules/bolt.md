## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-03 - Optimized Tab.to_dict serialization
**Learning:** Similar to feeds, `Tab.to_dict()` caused N+1 queries by fetching unread counts individually.
**Action:** Extend the aggregation pattern (GROUP BY) to all list endpoints that include calculated properties.
