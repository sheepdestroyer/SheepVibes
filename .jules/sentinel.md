## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
## 2026-03-12 - Stored XSS in Feed URL
**Vulnerability:** Adding a new feed allowed arbitrary strings, such as `javascript:alert(1)`, as the feed URL, bypassing URL scheme validation when creating the feed, resulting in Stored XSS. The `is_valid_feed_url` check was missing in the `add_feed` endpoint.
**Learning:** Even though `fetch_feed` will fail on non-http(s) schemes, the code explicitly allowed the feed to be saved anyway to handle temporary network failures. However, this permitted malicious schemes to be stored and subsequently rendered.
**Prevention:** Added `is_valid_feed_url` scheme validation strictly at the entry points (`add_feed`, `update_feed_url`) before attempting to fetch or save the feed to the database.
