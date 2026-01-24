## 2026-01-24 - N+1 Query Regression
**Learning:** Codebase state may contradict memories or documentation regarding optimizations. The `get_tabs` endpoint was documented as optimized but contained an N+1 query pattern.
**Action:** Always verify "known" optimizations with a measurement script before assuming they exist. Use `to_dict` with optional arguments to inject pre-calculated aggregates.
