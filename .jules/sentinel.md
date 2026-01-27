## 2026-01-27 - DefusedXML SAX Validation Trap
**Vulnerability:** Silent failure of `defusedxml.sax.parseString` when missing the `handler` argument, causing a fail-open condition in the XXE validator.
**Learning:** `defusedxml.sax.parseString` requires a `ContentHandler` instance as the second argument, unlike `minidom.parseString`. Failing to provide it raises a `TypeError`, which was caught by a broad `except Exception` block intended for non-XML content (JSON), effectively bypassing the security check.
**Prevention:** Always test the "failure" path of security controls. When using `defusedxml` (or any library), verify the API signature carefully. Avoid broad `except Exception` blocks around security critical code without logging or specific exception handling.
