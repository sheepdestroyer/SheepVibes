## 2026-01-25 - [Optimized get_tabs endpoint to fix N+1 query issue]
**Learning:** The `to_dict` method on models, when it includes database queries (like calculating unread counts), causes N+1 problems when iterating over a list of objects. Modifying `to_dict` to accept pre-calculated values allows for bulk fetching and optimization.
**Action:** Always check `to_dict` methods for database queries. If present, refactor to accept optional parameters for pre-fetched data, and perform bulk aggregation in the service/view layer.
