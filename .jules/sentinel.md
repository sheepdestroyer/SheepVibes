## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-06 - Missing Security Headers
**Vulnerability:** The application was missing critical security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), leaving it vulnerable to XSS, Clickjacking, and other client-side attacks.
**Learning:** Security headers are not automatically set by Flask and must be explicitly configured. Relying on implicit assumptions that "someone else handled it" (e.g., Nginx, or memory of past work) leads to security gaps.
**Prevention:** Implemented an `@app.after_request` handler to inject these headers into every response. Added a regression test `tests/unit/test_security_headers.py` to ensure they remain present.
