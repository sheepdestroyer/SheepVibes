## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-01-28 - N+1 in Tab.to_dict serialization
**Learning:** The `to_dict` pattern with internal queries was also present in `Tab` model, causing N+1 on `get_tabs`. The pattern of embedding queries in `to_dict` is a recurring anti-pattern in this codebase.
**Action:** Proactively check all `to_dict` methods for hidden queries and refactor to accept pre-calculated values when optimizing list endpoints.
