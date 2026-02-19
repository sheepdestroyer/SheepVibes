## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-05 - Strengthening OPML File Type Validation
**Vulnerability:** Weak file type validation allowed .txt files for OPML imports, which could lead to processing of unintended file types or bypasses of security controls.
**Learning:** Whitelists for file uploads should be as restrictive as possible. Including generic types like .txt in an XML-specific import path increases the attack surface unnecessarily.
**Prevention:** Removed .txt from the allowed extensions for OPML imports. Validated with a regression test to ensure only .opml and .xml are accepted.
