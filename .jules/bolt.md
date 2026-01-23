## 2026-01-23 - [N+1 Query in get_tabs]
**Learning:** Documented optimizations may be outdated or incorrect. Memory stated `get_tabs` was optimized for unread counts, but code analysis revealed an N+1 query pattern.
**Action:** Always verify "known" optimizations with profiling or code review, especially when performance is critical. Trust the code, not the docs.
