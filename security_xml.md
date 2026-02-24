# XML Security Guidelines

All XML processing in this project MUST adhere to these strict security policies to prevent XML External Entity (XXE) vulnerabilities and other XML-based attacks.

## 1. Centralized XML Utilities
Always use the centralized `backend/utils/xml_utils.py` module for XML generation and parsing instead of directly importing from `xml` or `defusedxml`.
- `UnsafeElement` / `UnsafeSubElement`: ONLY for generating XML trees.
- `tostring`: Safe generation of XML string.
- `safe_parse` / `safe_fromstring`: Parsing XML from untrusted data sources safely.

## 2. Forbidden Modules
NEVER use the following modules directly to parse untrusted XML:
- `xml.etree.ElementTree`
- `xml.sax`
- `xml.dom`

Use the aliases and wrappers exposed by `backend.utils.xml_utils` to ensure all XML data handling is inherently secure.
