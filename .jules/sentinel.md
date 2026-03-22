## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-22 - Missing Input Length Constraints Leading to 500 Errors
**Vulnerability:** API endpoints handling feed and tab creation/modification lacked explicit length checks corresponding to database schema constraints (e.g., `db.String(100)`, `db.String(500)`). Submitting strings exceeding these lengths caused unhandled database-level exceptions (`sqlalchemy.exc.DataError` or similar), resulting in 500 Internal Server Errors and potential Denial of Service (DoS).
**Learning:** Database schema constraints (`VARCHAR` limits) must be treated as defense-in-depth, not the primary validation layer. Relying on the DB to catch length errors can lead to unhandled exceptions exposing application state or causing instability, especially across different DB backends (e.g., SQLite silently accepts, Postgres throws errors).
**Prevention:** Explicit length validation (returning 400 Bad Request) and data truncation have been added to the API boundary for string inputs (`name`, `url`, `site_link`) before database interaction. Always enforce schema constraints at the API level.
