## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-03-13 - Stored XSS Prevention in Feed URLs
**Vulnerability:** Feed URLs were added and updated without validating that the URL scheme was safe (HTTP/HTTPS). This allowed an attacker to inject `javascript:` URLs via `add_feed` or `update_feed_url` endpoints, which could lead to Stored XSS if the frontend rendered them as links.
**Learning:** We must not rely exclusively on SSRF validation routines or fetch failures to reject bad input. If a fetch fails, the system still saved the malicious URL, causing Stored XSS. Explicit input validation prior to storage is strictly necessary.
**Prevention:** Enforced strict URL structure validation using `is_valid_feed_url` in both endpoints. All user input that will be stored must be validated against expected schemes and structure to prevent payload injection into the database.
