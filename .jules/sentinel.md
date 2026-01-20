## 2024-05-24 - XXE Vulnerability in OPML Import
**Vulnerability:** The application was using the standard `xml.etree.ElementTree` library to parse uploaded OPML files. This library is not secure against XML External Entity (XXE) attacks, allowing attackers to potentially read local files or cause DoS.
**Learning:** Always use `defusedxml` when parsing XML from untrusted sources (user uploads, external feeds). The standard library is only safe for XML you generate yourself.
**Prevention:** Replaced `ET.parse` with `defusedxml.ElementTree.parse` (aliased as `SafeET`). Added `defusedxml` to requirements.
