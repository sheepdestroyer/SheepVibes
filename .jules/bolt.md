## 2025-05-18 - N+1 Query in Tab List
**Learning:** SQLAlchemy `to_dict` methods that perform lazy loading queries inside a loop cause massive N+1 issues when serializing lists.
**Action:** Always use eager loading (e.g. `outerjoin` with aggregation) for list endpoints and pass computed values to `to_dict`.
