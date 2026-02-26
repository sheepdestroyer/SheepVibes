## 2026-02-26 - Optimized DOM rendering with DocumentFragment
**Learning:** Appending elements one-by-one to the DOM causes unnecessary reflows/repaints (N times). Using `DocumentFragment` batches these updates into a single append (1 time).
**Action:** Implemented `DocumentFragment` in `frontend/js/ui.js` (for tabs) and `frontend/js/app.js` (for feeds). Verified using a mocked DOM test script `tests/frontend/test_ui_optimization.mjs`.
