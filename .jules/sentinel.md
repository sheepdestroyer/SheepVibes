## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-15 - CSRF Protection for Vanilla JS Frontend
**Vulnerability:** Missing CSRF protection on API endpoints allowed cross-site requests to mutate state.
**Learning:** When using `Flask-WTF` with a vanilla JS frontend (no Jinja2 templates), the CSRF token must be explicitly exposed to the client. Using a non-HttpOnly cookie for the *token value* (separate from the HttpOnly *session cookie*) allows the frontend to read and send it in the `X-CSRFToken` header, satisfying `CSRFProtect`'s double-submit check.
**Prevention:** Configured `CSRFProtect` globally, added an `after_request` hook to set the `csrf_token` cookie, and updated the frontend `api.js` to automatically attach the token to all state-changing requests.
