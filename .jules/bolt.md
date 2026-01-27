## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-01-27 - Optimized Tab serialization
**Learning:** `Tab.to_dict()` also triggered N+1 queries for unread counts, similar to `Feed`. `sqlite:///:memory:` in `TESTING` mode requires careful setup order or `db.create_all()` will fail with `OperationalError`.
**Action:** Apply the same "pass aggregate data to `to_dict`" pattern to all models with computed properties. Ensure `TESTING` env var is set before importing app in test scripts.
