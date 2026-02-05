## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-05 - Optimized GET /api/tabs N+1
**Learning:** The N+1 anti-pattern found in `Feed` was also present in `Tab`, where `to_dict` executed a query.
**Action:** Systematically check all models' `to_dict` methods for hidden queries and refactor to accept pre-calculated values.
