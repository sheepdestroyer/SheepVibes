## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-31 - Missing Default Security Headers in Flask
**Vulnerability:** Flask does not inject standard security headers (CSP, X-Frame-Options, etc.) by default.
**Learning:** Frameworks often prioritize flexibility over security defaults. Explicit configuration via `@app.after_request` is necessary to ensure defense-in-depth against XSS, Clickjacking, and MIME-sniffing.
**Prevention:** Injected a standard set of security headers globally in `backend/app.py` and added a regression test `tests/unit/test_security_headers.py` to enforce their presence.
