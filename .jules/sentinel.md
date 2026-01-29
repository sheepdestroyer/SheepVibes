## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-26 - Missing Security Headers
**Vulnerability:** The application lacked standard security headers (CSP, X-Frame-Options, etc.), increasing susceptibility to XSS, Clickjacking, and other attacks.
**Learning:** Flask does not add these headers by default. Explicit middleware is required to enforce them.
**Prevention:** Implemented an `@app.after_request` handler in `backend/app.py` to inject X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Content-Security-Policy into all responses.
