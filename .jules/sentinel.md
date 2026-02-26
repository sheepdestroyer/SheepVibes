## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-23 - [Double Submit Cookie CSRF]
**Vulnerability:** Missing CSRF protection on API endpoints allowed state-changing requests (POST/PUT/DELETE) without verification.
**Learning:** Adding CSRF protection to an existing test suite requires careful configuration management. Tests often rely on `app.test_client()` which bypasses network layers but not `before_request` hooks. Explicitly disabling CSRF in the test fixture (conftest.py) is cleaner than patching it in every test.
**Prevention:** Always implement CSRF protection early. For stateless/SPA apps, Double Submit Cookie (using `httponly=False` cookie read by JS) is a robust pattern that avoids server-side session state.
