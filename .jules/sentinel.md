## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-03 - HTTP Security Headers Implementation
**Vulnerability:** Missing HTTP security headers (X-Frame-Options, CSP, etc.) allowed potential clickjacking, MIME sniffing, and XSS risks.
**Learning:** Flask does not set security headers by default. Relying on a reverse proxy is common but insufficient for "Defense in Depth" if the app is exposed directly or via simple containers.
**Prevention:** Implemented an `@app.after_request` hook to inject `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` into all responses. This secures the application at the source.
