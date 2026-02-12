## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-12 - Optimized Tab.to_dict serialization
**Learning:** Similar to `Feed`, `Tab.to_dict()` also had an N+1 query issue for unread counts.
**Action:** Applied the same pre-calculation strategy: aggregating counts in the route handler and passing them to `to_dict`. Confirmed optimization with a regression test counting queries.
