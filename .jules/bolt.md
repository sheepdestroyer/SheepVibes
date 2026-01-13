## 2026-01-13 - N+1 Query in Tab Serialization
**Learning:** The `to_dict` method in SQLAlchemy models often hides N+1 query problems when called in a loop, especially for calculated fields like `unread_count`. Flask-SQLAlchemy doesn't automatically optimize these count queries even with eager loading of relationships.
**Action:** When serializing lists of objects with aggregated fields, pre-calculate the aggregations in a single group-by query and pass the results to `to_dict` (or use a separate serialization helper) instead of relying on property accessors.
