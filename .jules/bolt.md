## 2026-01-26 - Optimized to_dict serialization
**Learning:** `Feed.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of feeds.
**Action:** Always pre-calculate aggregate data (like counts) in the main route handler and pass it to `to_dict` to keep serialization O(1).

## 2026-02-10 - Avoid COUNT(*) for limit enforcement
**Learning:** When enforcing a limit on a collection (e.g., "keep top N items"), counting the collection first is redundant. Instead, query for items *beyond* the offset N directly.
**Action:** Use a query with `order_by(DESC).offset(N).limit(BOUND)` to fetch IDs of excess items, then delete them using `DELETE WHERE id IN (...)`. Fetching IDs first avoids "subquery in DELETE" locking issues on SQLite and limiting the result set avoids OOM on massive collections.

## 2026-02-14 - Optimized Tab.to_dict serialization
**Learning:** `Tab.to_dict()` triggered a separate SQL query for unread counts, causing N+1 issues when serializing lists of tabs (e.g. in `get_tabs`).
**Action:** Implemented the same pattern as `Feed.to_dict()`: accept an optional `unread_count` parameter. Updated `get_tabs` to pre-calculate counts in a single query and pass them to `to_dict`.

## 2026-03-31 - Optimized FeedItem.to_iso_z_string
**Learning:** `FeedItem.to_iso_z_string` string manipulation logic was taking around 0.36 seconds per 100k invocations for naive datetimes from SQLite because it invoked `replace(tzinfo=timezone.utc)` and `replace("+00:00", "Z")` creating unneeded intermediate strings.
**Action:** Naive datetimes mapped to UTC from the DB can just append "Z" directly (`dt.isoformat() + "Z"`). This skips string `.replace()` and reduces overhead by ~66% for naive dates.
