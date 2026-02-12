## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
## 2026-02-12 - [Missing HTTP Security Headers]
**Vulnerability:** The application was missing critical HTTP security headers like X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** Default Flask applications do not include these headers, leaving them vulnerable to XSS, Clickjacking, and MIME-sniffing.
**Prevention:** Use an @app.after_request handler to inject these headers into every response.
