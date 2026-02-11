## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-11 - Tab.to_dict serialization N+1
**Learning:** The `Tab.to_dict` method also triggered a separate query for unread counts, causing N+1 issues when listing tabs. This reinforces the pattern that `to_dict` methods in this codebase are not pure serializers.
**Action:** When working with list endpoints, always check `to_dict` implementations for hidden queries and refactor to use bulk fetching.
