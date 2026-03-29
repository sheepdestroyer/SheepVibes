## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
## 2026-03-29 - Missing URL Validation in API Routes
**Vulnerability:** SSRF and Stored XSS due to missing URL validation on the `add_feed` and `update_feed_url` endpoints.
**Learning:** Even if a utility like `is_valid_feed_url` is created and used effectively in background tasks (like OPML imports), relying on user input purely as strings without validation in API layer (Flask blueprints) exposes the backend to SSRF and the frontend to Stored XSS.
**Prevention:** Enforce strict validation via `is_valid_feed_url` or similar URL parsing/validation immediately upon receiving input in the API endpoints to block invalid schemes like `javascript:` and `file:`.
