## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-01-26 - Weak File Type Validation in OPML Import
**Vulnerability:** The OPML import endpoint explicitly allowed `.txt` file extensions (`allowed_extensions = (".opml", ".xml", ".txt")`), opening up the application to weak file type validation attacks.
**Learning:** Even internal toolings like OPML import/export need strict file extension validation to prevent users from uploading unexpected file types that could potentially exploit other vulnerabilities (e.g., if a .txt file contained malicious payload or was stored incorrectly). Only `.opml` and `.xml` are strictly necessary for OPML functionality.
**Prevention:** Updated `allowed_extensions` in `backend/blueprints/opml.py` to strictly allow only `(".opml", ".xml")` and added a regression test `test_import_opml_txt_file_rejected` in `tests/unit/test_app.py` to enforce the rejection of `.txt` files in the future.
