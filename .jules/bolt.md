## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-10 - Avoid COUNT(*) for limit enforcement
**Learning:** When enforcing a limit on a collection (e.g., "keep top N items"), counting the collection first is redundant. Instead, query for items *beyond* the offset N directly.
**Action:** Use a query with `order_by(DESC).offset(N).limit(BOUND)` to fetch IDs of excess items, then delete them using `DELETE WHERE id IN (...)`. Fetching IDs first avoids "subquery in DELETE" locking issues on SQLite and limiting the result set avoids OOM on massive collections.

## 2026-02-14 - Optimized Tab.to_dict serialization
**Learning:** `Tab.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of tabs (e.g. in `get_tabs`).
**Action:** Implemented the same pattern as `Feed.to_dict()`: accept an optional `unread_count` parameter. Updated `get_tabs` to pre-calculate counts in a single query and pass them to `to_dict`.

## 2026-02-28 - Optimized feed updates with IN clauses
**Learning:** The feed update process (`_collect_new_items`) previously fetched all existing feed items into memory for deduplication. This caused an O(N) memory and time bottleneck, scaling linearly with the number of retained feed items, even if only a few new items were available in the parsed feed.
**Action:** Extract candidates (guids/links) from the incoming feed first, and use a SQLAlchemy `IN` clause with `or_` to query only the potentially conflicting items from the database. Fall back to the original fetch-all method only if the number of candidates is large (>=500) to avoid SQLite parameter limits (`>999`). When 0 items are available in the feed, use `sqlalchemy.false()` to ensure no db queries are run.