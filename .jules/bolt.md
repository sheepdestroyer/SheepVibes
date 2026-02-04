## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-04 - Eliminated N+1 in get_tabs
**Learning:** `get_tabs` triggered N+1 queries by calling `Tab.to_dict()` in a loop, where each call executed a count query.
**Action:** Implemented bulk fetching of unread counts using `group_by` and passed the counts to `to_dict`, reducing queries from N+1 to 2.
