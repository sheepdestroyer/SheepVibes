## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-26 - Weak File Type Validation in OPML Import
**Vulnerability:** Weak File Type Validation allowing `.txt` files to be uploaded as OPML.
**Learning:** `backend/blueprints/opml.py` explicitly allowed `.txt` extensions in the `_validate_opml_file_request` method, which is not an expected format for OPML/XML files. While perhaps low-severity unless files are served directly, it breaks the principle of least privilege for file types.
**Prevention:** Hardened validation by strictly checking for `.opml` and `.xml` extensions, and created a specific regression test `test_import_opml_txt_file_rejected`.
