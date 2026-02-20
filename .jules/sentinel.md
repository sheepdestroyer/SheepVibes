## 2026-02-20 - Stored XSS in Feed URLs
**Vulnerability:** The `add_feed` and `update_feed_url` endpoints in `backend/blueprints/feeds.py` blindly trusted user input for `url` and `site_link`, allowing `javascript:` schemes to be stored and later executed by the frontend.
**Learning:** Even though `feed_service.py` had validation functions (`is_valid_feed_url`), they were not being consistently enforced at the API entry points (Blueprints). Validation must happen as early as possible, right at the API boundary.
**Prevention:** Imported and enforced `is_valid_feed_url` and `validate_link_structure` in the API endpoints. Added a regression test `tests/unit/test_feed_stored_xss.py` to prevent reintroduction.

## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
