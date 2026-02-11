## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-11 - Missing Security Headers
**Vulnerability:** The application lacked essential HTTP security headers like `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
**Learning:** Frameworks like Flask do not inject these security headers by default. Developers must explicitly configure them to protect against XSS, clickjacking, and other common web vulnerabilities.
**Prevention:** Implemented a global `@app.after_request` handler to inject these headers into all responses, ensuring consistent protection across the application. Added a dedicated regression test `tests/unit/test_security_headers.py` to prevent future removal.
