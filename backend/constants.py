DEFAULT_FEED_ITEMS_LIMIT = 10
MAX_PAGINATION_LIMIT = 100
DEFAULT_PAGINATION_LIMIT = 10
UPDATE_INTERVAL_MINUTES_DEFAULT = 15
OPML_AUTOSAVE_INTERVAL_MINUTES_DEFAULT = 60
# Maximum number of items to keep per feed for cache eviction
MAX_ITEMS_PER_FEED = 100
# Chunk size for batched delete operations to avoid SQLite parameter limits
DELETE_CHUNK_SIZE = 500
DEFAULT_OPML_IMPORT_TAB_NAME = "Imported Feeds"
SKIPPED_FOLDER_TYPES = {
    "netvibes-specific",
    "hidden",
    "UWA",
    "Webnote",
    "LinkModule",
}
