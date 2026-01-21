## 2024-05-23 - N+1 Query in Model Serialization
**Learning:** Model `to_dict` methods that perform database queries (like `count()`) cause hidden N+1 performance issues when serializing lists of objects.
**Action:** When serializing lists, always pre-calculate aggregate data (like counts) in a single bulk query and pass it to `to_dict` as an argument, rather than letting each object query individually.
