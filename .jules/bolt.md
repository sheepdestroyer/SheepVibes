## 2025-05-23 - Parallel Feed Fetching
**Learning:** Python's `ThreadPoolExecutor` is highly effective for I/O-bound tasks like fetching multiple RSS feeds. However, SQLAlchemy sessions are not thread-safe.
**Action:** The pattern of "fetch in parallel threads, process/write to DB sequentially in main thread" is robust and avoids complex session management issues. Always separate side-effect-free I/O from DB operations when parallelizing.
