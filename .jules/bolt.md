## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-09 - Optimized get_tabs with GROUP BY
**Learning:** `Tab.to_dict()` triggered N+1 queries when listing tabs because it counted unread items individually.
**Action:** Use `db.session.query(...).group_by(Feed.tab_id)` to pre-calculate unread counts in a single query and pass them to `to_dict`.
