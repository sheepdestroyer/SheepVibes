## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-04 - HTTP Security Headers Implementation
**Vulnerability:** The application was missing standard HTTP security headers (CSP, X-Frame-Options, etc.), increasing risk of XSS, Clickjacking, and MIME sniffing.
**Learning:** Security headers are not enabled by default in Flask; they must be explicitly injected via an after_request hook or a middleware.
**Prevention:** Implemented a global `@app.after_request` handler to inject CSP, HSTS equivalent (X-Content-Type-Options), and other headers. Added a regression test `tests/unit/test_security_headers.py` to ensure they persist.
