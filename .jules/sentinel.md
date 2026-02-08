## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-08 - Missing HTTP Security Headers
**Vulnerability:** The application lacked essential HTTP security headers (CSP, HSTS, X-Content-Type-Options, etc.), leaving it vulnerable to Clickjacking, XSS, and MIME-sniffing attacks.
**Learning:** Framework defaults (like Flask's) prioritize compatibility over security and do not include these headers out-of-the-box. Security headers must be explicitly configured.
**Prevention:** Implemented an `@app.after_request` handler in `backend/app.py` to inject strict security headers (CSP, X-Frame-Options, etc.) on every response. Added a regression test `tests/unit/test_security_headers.py` to ensure they remain present.
