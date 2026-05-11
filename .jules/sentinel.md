## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-16 - Input Length Validation
**Vulnerability:** Missing length limits on string inputs (e.g., tab names, feed URLs, feed names) could lead to Database Operational Errors (due to exceeding column lengths) or mild Denial of Service (DoS) by sending excessively large payloads.
**Learning:** Database schema constraints (like `db.String(100)`) are not automatically enforced at the API layer in Flask/SQLAlchemy without explicit validation. Relying on the database to catch these errors leads to messy `500 Internal Server Error` responses and unnecessary database load.
**Prevention:** Always implement explicit length validation at the API endpoint level (e.g., `if len(name) > 100: return 400`) before interacting with the database to ensure fail-safe and user-friendly `400 Bad Request` responses.
