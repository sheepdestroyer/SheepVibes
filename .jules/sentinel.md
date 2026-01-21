## 2026-01-21 - OPML Import XXE Vulnerability
**Vulnerability:** The OPML import feature used `xml.etree.ElementTree` to parse user-uploaded files, which is vulnerable to XML Entity Expansion (Billion Laughs) and XXE attacks.
**Learning:** Standard Python XML libraries are insecure by default for untrusted input.
**Prevention:** Always use `defusedxml.ElementTree` (aliased as `SafeET`) for parsing untrusted XML, and catch `DefusedXmlException`. Use standard ET only for generation.
