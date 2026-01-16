## 2026-01-16 - Optimized get_tabs N+1
**Learning:** `get_tabs` had an N+1 query issue (one query per tab for unread counts). Solved by fetching all counts in a single aggregation query and mapping them to tabs.
**Action:** Always check `to_dict` methods for N+1 queries when lists are returned. Use `db.func` for consistency.
