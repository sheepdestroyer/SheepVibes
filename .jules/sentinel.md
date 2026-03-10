## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-10 - Stored XSS & SSRF Prevention in Feed URLs
**Vulnerability:** The `/api/feeds` (`add_feed`) and `/api/feeds/<feed_id>` (`update_feed_url`) endpoints allowed any non-empty string as a feed URL. If `fetch_feed` failed, it gracefully degraded to using the malicious string as the feed name, resulting in Stored XSS via `javascript:` payloads and potential SSRF by not restricting URL schemes prior to fetching.
**Learning:** Graceful degradation on failure is good for usability, but without strict input validation beforehand, it can unintentionally store and serve malicious payloads. Existing internal utility functions (`is_valid_feed_url`) must be applied across all entry points, not just some.
**Prevention:** Imported and enforced `is_valid_feed_url(url)` in both the `add_feed` and `update_feed_url` endpoints. This ensures only properly structured URLs with valid schemes (`http`, `https`) are processed and saved, rejecting all invalid or malicious inputs early.
