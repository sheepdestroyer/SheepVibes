## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-29 - Missing HTTP Security Headers
**Vulnerability:** The application was missing standard HTTP security headers (CSP, X-Frame-Options, etc.), leaving it more exposed to XSS and Clickjacking.
**Learning:** Vanilla JS frontends that modify DOM styles often require `style-src 'self' 'unsafe-inline'` in the CSP. A strict CSP blocking inline styles would break the frontend.
**Prevention:** Implemented an `@app.after_request` handler in Flask to inject `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` headers globally.
