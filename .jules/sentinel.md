## 2026-01-19 - XML Parsing Vulnerability in OPML Import
**Vulnerability:** The application used `xml.etree.ElementTree` to parse uploaded OPML files, which is vulnerable to XXE and Billion Laughs (DoS) attacks.
**Learning:** Even if the default environment's parser limits some XXE attacks (like external entities in attributes), it remains vulnerable to entity expansion DoS (Billion Laughs) and might be vulnerable to XXE in other environments or configurations.
**Prevention:** Use `defusedxml.ElementTree` (aliased as `SafeET`) for parsing all untrusted XML content. Maintain `xml.etree.ElementTree` (aliased as `StandardET`) only for XML generation where `defusedxml` is not applicable.
