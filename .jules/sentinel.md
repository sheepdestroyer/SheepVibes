## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-01 - Security Headers & CSP Implementation
**Vulnerability:** Missing HTTP Security Headers (Content-Security-Policy, X-Frame-Options, etc.) left the application vulnerable to XSS, Clickjacking, and MIME sniffing.
**Learning:** For an RSS reader, a strict CSP is challenging because external images must be loaded. `img-src 'self' data: https:` is a necessary compromise. Also, vanilla JS frontends often rely on inline styles, necessitating `style-src 'self' 'unsafe-inline'`.
**Prevention:** Implemented `@app.after_request` middleware to inject strict CSP, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy headers. Verified frontend compatibility with Playwright.
