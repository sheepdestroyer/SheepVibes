## 2025-02-18 - XXE in OPML Import
**Vulnerability:** The OPML import feature used `xml.etree.ElementTree` to parse user-uploaded XML files, which is vulnerable to XXE (External Entity Expansion) and Billion Laughs (DoS) attacks.
**Learning:** Even when the primary feed parser (`feedparser`) is secure, secondary XML handling (like OPML or configuration files) using standard libraries remains a critical attack vector.
**Prevention:** Always use `defusedxml.ElementTree` (aliased as `SafeET`) for parsing untrusted XML. Standard `xml.etree.ElementTree` should only be used for generating/exporting XML data.
