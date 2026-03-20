## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-20 - API-Layer Enforcement of SQLAlchemy String Constraints
**Vulnerability:** Input fields (Tab names, Feed URLs, custom feed names) lacked explicit length validation at the API layer, despite the database schema having strict `db.String` length limits (e.g., 100, 500, 200).
**Learning:** In Flask/SQLAlchemy applications, database constraints do not automatically reject invalid inputs before querying the database; instead, passing oversized strings leads to unpredictable `500 Internal Server Error` responses and unnecessary load on the DB connection pool. Also, uncontrolled data ingested from external sources (RSS feed titles/links) could exceed database limits on updates.
**Prevention:** Always enforce string length limits manually at the API route level (returning a structured `400 Bad Request` before calling `db.session`), and actively truncate untrusted external data (like parsed RSS fields) to fit within DB constraints prior to committing.
