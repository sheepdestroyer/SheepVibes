## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-26 - Stored XSS via Feed URL
**Vulnerability:** The application validated feed accessibility via `fetch_feed` but fell back to storing the raw user-provided URL if fetching failed. This allowed attackers to store `javascript:` URLs which were later rendered as clickable links in the frontend.
**Learning:** Input validation must occur *before* processing logic. Treating a fetch failure as a valid "offline" feed state without re-validating the input format (scheme) created a bypass.
**Prevention:** Explicitly validate URL schemes (http/https) at the API boundary (controller level) before attempting any business logic or storage. Added `is_valid_feed_url` check in `add_feed` and `update_feed_url`.
