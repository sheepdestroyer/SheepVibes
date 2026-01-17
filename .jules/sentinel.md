## 2026-01-17 - Safe XML Parsing vs Generation
**Vulnerability:** XXE risk in OPML import using standard `xml.etree.ElementTree`.
**Learning:** `defusedxml.ElementTree` is API-compatible for *parsing* but lacks the `Element()` factory and other generation tools found in standard `ET`. Replacing the import globally breaks XML generation code (e.g., OPML export).
**Prevention:** Use `defusedxml` explicitly for parsing untrusted input (`SafeET.parse`), but retain standard `xml.etree.ElementTree` for generating XML from trusted internal data (`StandardET.Element`).
