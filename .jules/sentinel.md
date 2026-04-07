## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-02-09 - Weak File Type Validation in OPML Import
**Vulnerability:** OPML import feature historically allowed `.txt` extensions in addition to standard XML/OPML extensions (`.xml`, `.opml`).
**Learning:** Accepting overly broad file extensions for structured data imports increases the attack surface for file-handling vulnerabilities or unexpected content processing by backend parsers. The validation logic must strictly align with the expected data types.
**Prevention:** Enforced strict allowlist validation strictly for `.opml` and `.xml` file extensions in the OPML import route and introduced a regression test (`test_import_opml_txt_file_rejected`) to actively prevent weak type acceptance.
