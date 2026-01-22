## 2026-01-22 - Optimized get_tabs N+1 Query
**Learning:** Iterating over SQLAlchemy model instances and accessing properties that trigger subqueries (like unread counts in `to_dict`) causes severe N+1 performance degradation.
**Action:** Always pre-calculate aggregated stats (like counts) using a single `group_by` query and pass them into serialization methods to maintain O(1) query performance per request.
