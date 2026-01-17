## 2026-01-17 - N+1 in Model Serialization
**Learning:** The `to_dict` methods on models (`Tab`, `Feed`) were triggering individual queries for unread counts, causing N+1 issues when serializing lists.
**Action:** When adding computed fields to `to_dict`, support passing pre-calculated values as arguments to allow bulk fetching in the service layer/route handler.
