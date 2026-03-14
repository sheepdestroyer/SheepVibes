## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
## 2023-10-27 - Strict URL Scheme Validation for XSS Prevention
**Vulnerability:** Feed URLs were being saved directly to the database even if the feed fetching failed. These URLs were subsequently used as `href` attributes in the frontend's widget titles. An attacker could add a feed with a `javascript:alert(1)` URI, leading to Stored XSS when a user clicks the title.
**Learning:** Relying purely on network-layer checks (which implicitly fail on non-HTTP schemes) during the fetch process is insufficient because the application state may still save the malicious input if the fetch error is handled gracefully.
**Prevention:** Always validate URL schemes explicitly at the API boundary using a whitelist (e.g., `http`, `https`) *before* saving any user-supplied URL to the database or using it in contexts like `href` attributes.
