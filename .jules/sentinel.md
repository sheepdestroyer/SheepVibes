## 2026-01-26 - XXE Prevention in Feed Parsing
**Vulnerability:** `feedparser` library relies on standard XML libraries which may be vulnerable to XXE (XML External Entity) attacks if not configured securely or if the environment defaults are insecure.
**Learning:** Even if the current environment's Python version (e.g. 3.12) defaults to safe XML parsing, relying on implicit defaults is risky. Explicit validation using `defusedxml` is required for robust security.
**Prevention:** Implemented a pre-validation step using `defusedxml.sax.parseString` to check for DTDs and entities before passing content to `feedparser`. This ensures XXE attacks are blocked regardless of the underlying parser's configuration.

## 2024-05-24 - DOM XSS Prevention Pattern
**Vulnerability:** Use of `innerHTML` for rendering static messages (e.g., empty states) in the vanilla JS frontend creates an unnecessary risk of DOM-based XSS if those strings are ever refactored to include user input.
**Learning:** In vanilla JavaScript without a framework to automatically escape content, relying on `innerHTML` violates the principle of defense-in-depth.
**Prevention:** Adopt a strict project-wide pattern of using `document.createElement`, `.textContent`, and `.replaceChildren()` for all DOM updates, completely avoiding `innerHTML` even for hardcoded strings.
