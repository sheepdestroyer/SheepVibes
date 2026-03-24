## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-24 - Missing Input Validation on Feed URLs Allows Invalid Schemes
**Vulnerability:** The API endpoints for adding and updating feeds (`add_feed` and `update_feed_url` in `backend/blueprints/feeds.py`) did not validate the URL scheme before attempting to fetch the feed or storing it in the database.
**Learning:** While the feed fetcher itself may use safe resolvers, storing unvalidated user input directly in the database as a URL can lead to Stored XSS (if rendered unsafely on the frontend) and increases the risk of SSRF or malicious redirects if the fetcher or frontend isn't perfectly configured to handle exotic schemes.
**Prevention:** Added an explicit `is_valid_feed_url` check directly at the API boundary in `backend/blueprints/feeds.py` to ensure only `http` and `https` schemes are accepted.
