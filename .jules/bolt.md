## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-10 - Avoid COUNT(*) for limit enforcement
**Learning:** When enforcing a limit on a collection (e.g., "keep top N items"), counting the collection first is redundant. Instead, query for items *beyond* the offset N directly.
**Action:** Use a query with `order_by(DESC).offset(N).limit(BOUND)` to fetch IDs of excess items, then delete them using `DELETE WHERE id IN (...)`. Fetching IDs first avoids "subquery in DELETE" locking issues on SQLite and limiting the result set avoids OOM on massive collections.

## 2026-02-14 - Optimized Tab.to_dict serialization
**Learning:** `Tab.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of tabs (e.g. in `get_tabs`).
**Action:** Implemented the same pattern as `Feed.to_dict()`: accept an optional `unread_count` parameter. Updated `get_tabs` to pre-calculate counts in a single query and pass them to `to_dict`.

## 2026-02-16 - Batching DOM Updates with DocumentFragment

**Learning:** Appending multiple elements to a live DOM container one by one in a loop can cause significant performance degradation due to multiple layout reflows and repaints. Using a `DocumentFragment` to batch these operations in memory before a single append to the DOM can improve rendering performance by ~50% for large lists.

**Action:** Always use `DocumentFragment` when rendering lists of elements in vanilla JavaScript to ensure optimal performance and minimize browser work.
