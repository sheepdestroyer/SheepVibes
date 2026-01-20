## 2026-01-20 - N+1 Query Fix in get_tabs
**Learning:** `Tab.to_dict()` contained a query to calculate unread counts, causing N+1 queries when iterating over a list of tabs.
**Action:** When serializing lists of objects that require aggregated data (like counts), pre-calculate the data in a single group-by query and pass it to the serialization method or attach it to the objects, instead of querying inside the loop/serialization method.
