## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-07 - Missing HTTP Security Headers
**Vulnerability:** The application was serving responses without critical HTTP security headers (CSP, X-Frame-Options, etc.), leaving it vulnerable to XSS, Clickjacking, and MIME-sniffing attacks.
**Learning:** Flask does not inject these headers by default. Developers must explicitly configure them or use a library like `flask-talisman`. Relying on default framework behavior often leaves security gaps.
**Prevention:** Implemented an `@app.after_request` handler to inject a strict Content Security Policy (CSP) and other recommended headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) for every response.
