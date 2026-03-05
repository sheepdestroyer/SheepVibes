## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.
## 2025-03-05 - Restrict allowed extensions for OPML import
**Vulnerability:** OPML/XML import endpoint allowed `.txt` extensions, bypassing weak file type validation. This could result in uploading arbitrary text data, leading to various issues depending on how the application handles it down the line or potentially tricking the parser if there is embedded/partial XML.
**Learning:** File type validation based purely on extensions must be restricted to explicitly expected formats. Allowing `.txt` for files destined for XML parsers undermines defense-in-depth, even if a robust XML parser is used.
**Prevention:** Strictly restrict allowed extensions for file uploads to only valid representations of that data (e.g. `.opml` and `.xml` for OPML feeds) and never allow generic ones like `.txt`. Ensure test coverage rejects explicitly disallowed file types.
