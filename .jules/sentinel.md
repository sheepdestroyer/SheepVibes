## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2026-04-23 - Weak File Type Validation in OPML Import
**Vulnerability:** The OPML import endpoint allowed files with a `.txt` extension to be uploaded and parsed as XML.
**Learning:** Permitting `.txt` extensions for XML-based file uploads (like OPML) bypasses explicit intent and can increase the attack surface for file upload vulnerabilities or unexpected parser behavior.
**Prevention:** Strictly restrict allowed extensions for OPML uploads to only `.opml` and `.xml`. Added a regression test `test_import_opml_txt_file_rejected` to enforce this constraint.
