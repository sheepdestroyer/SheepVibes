# Import necessary libraries
# Use dateutil for robust date parsing
import concurrent.futures
import datetime  # Import the full module
import ipaddress
import logging  # Standard logging
import os
import socket
import urllib.request
from datetime import timezone  # Specifically import timezone
from urllib.parse import urlparse

import feedparser
from dateutil import parser as date_parser
from sqlalchemy.exc import IntegrityError

# Import database models from the new models.py
from .models import Feed, FeedItem, db

# Set up logger for this module
logger = logging.getLogger(__name__)

# Maximum number of items to keep per feed for cache eviction
MAX_ITEMS_PER_FEED = 100

# Maximum number of concurrent feed fetches
# I/O bound tasks can handle more workers than CPU cores
try:
    _cpu_count = os.cpu_count() or 1
except Exception:
    _cpu_count = 1

MAX_CONCURRENT_FETCHES = int(
    os.environ.get("FEED_FETCH_MAX_WORKERS", _cpu_count * 5)
)

# --- Helper Functions ---


def parse_published_time(entry):
    """Attempts to parse the published time from a feed entry.

    Args:
        entry (feedparser.FeedParserDict): A feedparser entry object.

    Returns:
        datetime.datetime: A datetime object representing the published time
                           (UTC aware). Falls back to the current UTC time if
                           parsing fails.
    """
    parsed_dt = None
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            parsed_dt = datetime.datetime(
                *entry.published_parsed[:6], tzinfo=timezone.utc
            )
        except (TypeError, ValueError) as e:
            logger.debug(
                "Failed to parse 'published_parsed' for entry %s: %s",
                entry.get("link", "[no link]"),
                e,
            )
            parsed_dt = None

    if parsed_dt is None:
        # Try common date fields using dateutil.parser for more flexibility
        # Added 'dc:date' as observed in some feeds
        date_fields = ["published", "updated", "created", "dc:date"]
        for field in date_fields:
            if hasattr(entry, field):
                field_value = getattr(entry, field)
                if field_value:
                    try:
                        parsed_dt = date_parser.parse(field_value)
                        if parsed_dt:
                            break
                    except (ValueError, TypeError, OverflowError) as e:
                        logger.debug(
                            "Specific parsing error for date field '%s' for entry %s (%s): %s",
                            field,
                            entry.get("link", "[no link]"),
                            type(e).__name__,
                            e,
                        )
                        continue
                    except Exception as e:
                        logger.warning(
                            "Generic parsing error for date field '%s' for entry %s (%s): %s",
                            field,
                            entry.get("link", "[no link]"),
                            type(e).__name__,
                            e,
                        )
                        continue

    if parsed_dt:
        # Ensure the datetime is UTC timezone-aware
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        else:
            parsed_dt = parsed_dt.astimezone(timezone.utc)
        return parsed_dt

    logger.warning(
        "Could not parse published time for entry: %s. Using current time as fallback.",
        entry.get("link", "[no link]"),
    )
    return datetime.datetime.now(timezone.utc)


# --- Core Feed Processing Functions ---


def validate_and_resolve_url(url):
    """Validates URL and resolves IP to prevent SSRF (returns safe IP or None)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Blocked unsupported URL scheme: %s", parsed.scheme)
            return None, None

        hostname = parsed.hostname
        if not hostname:
            return None, None

        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            if os.environ.get("TESTING") == "true":
                return "127.0.0.1", hostname  # Fallback for tests
            logger.warning("Could not resolve hostname: %s", hostname)
            return None, None

        safe_ip = None
        for res in addr_info:
            ip_str = res[4][0]
            clean_ip_str = ip_str.split("%")[0]
            try:
                ip = ipaddress.ip_address(clean_ip_str)
                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    safe_url = f"{parsed.scheme}://{hostname}"
                    logger.warning(
                        "Blocked SSRF attempt: %s -> %s", safe_url, ip)
                    return None, None
                safe_ip = ip_str  # Keep valid IP string
                break  # Found a safe IP
            except ValueError:
                continue

        return safe_ip, hostname
    except Exception:
        logger.exception("Error validating URL safety")
        return None, None


def _fetch_feed_content(feed_id, feed_url):
    """
    Helper function to fetch feed content in a separate thread.
    Returns (feed_id, parsed_feed).
    This function must be side-effect-free regarding the database.
    """
    try:
        parsed_feed = fetch_feed(feed_url)
        return feed_id, parsed_feed
    except Exception as e:
        logger.exception("Error in fetch thread for feed %s: %s", feed_url, e)
        return feed_id, None


def _process_fetch_result(feed_db_obj, parsed_feed):
    """
    Helper function to process the result of a feed fetch (parsed_feed).
    Handles empty feeds, database updates, and calling process_feed_entries.

    Args:
        feed_db_obj (Feed): The database feed object.
        parsed_feed (feedparser.FeedParserDict): The parsed feed result.

    Returns:
        tuple: (success, new_items_count, tab_id)
    """
    if not parsed_feed:
        logger.error(
            "Fetching content for feed '%s' (ID: %s) failed (None returned).",
            feed_db_obj.name,
            feed_db_obj.id,
        )
        return False, 0, feed_db_obj.tab_id

    # Handle cases where feed is fetched but has no entries (common for new or empty feeds)
    if not parsed_feed.entries:
        logger.info(
            "Feed '%s' (ID: %s) fetched successfully but contained no entries.",
            feed_db_obj.name,
            feed_db_obj.id,
        )
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(
                "Error committing feed update (no entries) for %s: %s",
                feed_db_obj.name,
                e,
                exc_info=True,
            )
            return False, 0, feed_db_obj.tab_id
        return True, 0, feed_db_obj.tab_id

    try:
        new_items = process_feed_entries(feed_db_obj, parsed_feed)
        # process_feed_entries handles its own logging and commits for items and last_updated_time.
        return True, new_items, feed_db_obj.tab_id
    except Exception as e:
        logger.error(
            "An unexpected error occurred during entry processing for feed '%s' (ID: %s): %s",
            feed_db_obj.name,
            feed_db_obj.id,
            e,
            exc_info=True,
        )
        return False, 0, feed_db_obj.tab_id


def fetch_feed(feed_url):
    """Fetches and parses a feed, preventing SSRF via IP pinning."""
    safe_ip, hostname = validate_and_resolve_url(feed_url)
    if not safe_ip:
        return None

    logger.info("Fetching feed: %s", feed_url)
    try:
        # Prevent TOCTOU: Fetch using the validated IP
        parsed = urlparse(feed_url)
        # Only rewrite URL for HTTP to avoid SSL hostname mismatch
        # WARNING: This implementation is vulnerable to DNS Rebinding for HTTPS.
        # urllib cannot easily force an IP while validating the SNI/Hostname.
        # For HTTP, we rewrite the URL. For HTTPS, we unfortunately rely on the
        # race-condition-prone check above.
        if parsed.scheme == "http":
            target_url = parsed._replace(netloc=safe_ip).geturl()
        else:
            target_url = feed_url

        req = urllib.request.Request(
            target_url, headers={"Host": hostname,
                                 "User-Agent": "SheepVibes/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
            content = response.read()

        parsed_feed = feedparser.parse(content)
        # feedparser.parse(bytes) doesn't set bozo for network errors, but we handled network above.
        if parsed_feed.bozo:
            logger.warning(
                "Feed parsing warning: %s", parsed_feed.get("bozo_exception")
            )

        return parsed_feed

    except Exception as e:
        logger.error("Error fetching feed %s: %s", feed_url, e, exc_info=True)
        return None


def process_feed_entries(feed_db_obj, parsed_feed):
    """Processes entries from a parsed feed and adds new items to the database.

    Args:
        feed_db_obj (Feed): The Feed database object (SQLAlchemy model instance).
        parsed_feed (feedparser.FeedParserDict): The dictionary object returned
                                                 by feedparser.parse().

    Returns:
        int: The number of new items added to the database for this feed.
    """
    if not parsed_feed:
        logger.error(
            "process_feed_entries called with a null parsed_feed for feed ID %s",
            feed_db_obj.id if feed_db_obj else "Unknown",
        )
        return 0

    # These sets track items *within the current batch being processed*
    batch_processed_guids = set()
    batch_processed_links = set()

    # Get existing items *for this specific feed* to support updates/deduplication
    existing_items = FeedItem.query.filter_by(feed_id=feed_db_obj.id).all()
    # Map them for quick lookup
    existing_items_by_guid = {
        item.guid: item for item in existing_items if item.guid}
    existing_items_by_link = {
        item.link: item for item in existing_items if item.link}

    new_title = parsed_feed.feed.get("title")
    if new_title and new_title.strip() and new_title != feed_db_obj.name:
        logger.info("Updating feed title for '%s' to '%s'",
                    feed_db_obj.name, new_title)
        feed_db_obj.name = new_title

    # Update site_link if available and different
    # This is typically the website link
    new_site_link = parsed_feed.feed.get("link")
    if (
        new_site_link
        and new_site_link.strip()
        and new_site_link != feed_db_obj.site_link
    ):
        logger.info(
            "Updating feed site_link for '%s' from '%s' to '%s'",
            feed_db_obj.name,
            feed_db_obj.site_link,
            new_site_link,
        )
        feed_db_obj.site_link = new_site_link
    elif (
        not feed_db_obj.site_link and new_site_link and new_site_link.strip()
    ):  # If current is null, set it
        logger.info(
            "Setting feed site_link for '%s' to '%s'",
            feed_db_obj.name,
            new_site_link,
        )
        feed_db_obj.site_link = new_site_link

    logger.info(
        "Processing %s entries for feed: %s (ID: %s)",
        len(parsed_feed.entries),
        feed_db_obj.name,
        feed_db_obj.id,
    )

    items_to_add = []

    for entry in parsed_feed.entries:
        entry_title = entry.get("title", "[No Title]")
        entry_link = entry.get("link")
        # This is what feedparser provides as 'id'
        feedparser_id = entry.get("id")

        if not entry_link:  # Link is essential
            logger.warning(
                "Skipping entry titled '%s' for feed '%s' due to missing link. (feedparser ID: %s)",
                entry_title[:100],
                feed_db_obj.name,
                feedparser_id if feedparser_id else "N/A",
            )
            continue

        # Determine the GUID for deduplication. Prioritize the entry's 'id' field from
        # feedparser. If it's not present or is an empty string, fall back to the link.
        # This ensures a stable unique identifier for each item, which is crucial for
        # the (feed_id, guid) unique constraint in the database.
        db_guid = feedparser_id or entry_link

        # --- Deduplication & Update Logic ---
        # Look for an existing item by GUID or Link
        existing_item = None
        if db_guid:
            existing_item = existing_items_by_guid.get(db_guid)
        if not existing_item and entry_link:
            existing_item = existing_items_by_link.get(entry_link)

        if existing_item:
            # If item exists, check if any tracked property changed
            item_changed = False
            if entry_title and entry_title != existing_item.title:
                logger.info(
                    "Updating title for existing item '%s' to '%s' in feed '%s'",
                    existing_item.title,
                    entry_title,
                    feed_db_obj.name,
                )
                existing_item.title = entry_title
                item_changed = True

            # In the future, we could check summary, published_time etc. here.

            if item_changed:
                db.session.add(existing_item)
                # Note: We don't increment new_items_count for updates,
                # but we do want to commit the change.
            continue

        # 2. Check against items already processed *in this current batch*
        is_batch_duplicate = False
        if db_guid:  # If this item has a "true" GUID
            if db_guid in batch_processed_guids:
                logger.warning(
                    "Skipping item (true GUID: %s, link: %s) for feed '%s', duplicate true GUID in current fetch batch.",
                    db_guid,
                    entry_link,
                    feed_db_obj.name,
                )
                is_batch_duplicate = True
        else:  # No "true" GUID (db_guid is None), so batch uniqueness relies on the link
            if entry_link in batch_processed_links:
                logger.warning(
                    "Skipping item (link: %s) for feed '%s', it has no true GUID and its link is a duplicate in current fetch batch.",
                    entry_link,
                    feed_db_obj.name,
                )
                is_batch_duplicate = True

        if is_batch_duplicate:
            continue

        # If we reach here, the item is considered new.
        # Add its identifiers to the batch processed sets for subsequent checks within this batch.
        if db_guid:
            batch_processed_guids.add(db_guid)
        # Always add the link to batch_processed_links. For items with true GUIDs, this helps
        # catch subsequent items in the same batch that *lack* a true GUID but share the same link.
        # For items without true GUIDs, this is their primary batch duplicate check.
        batch_processed_links.add(entry_link)

        published_time = parse_published_time(
            entry)  # Already falls back to now()

        new_item = FeedItem(
            feed_id=feed_db_obj.id,
            title=entry_title,
            link=entry_link,
            published_time=published_time,
            guid=db_guid,  # Always the entry's link per the new GUID strategy
        )
        items_to_add.append(new_item)

    if not items_to_add:
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()  # Commit to save updated last_updated_time
        except Exception as e:  # Catch potential errors during this commit
            db.session.rollback()
            logger.error(
                "Error committing feed update (no new items) for %s: %s",
                feed_db_obj.name,
                e,
                exc_info=True,
            )
        return 0

    committed_items_count = 0
    try:
        db.session.add_all(items_to_add)
        feed_db_obj.last_updated_time = datetime.datetime.now(
            timezone.utc
        )  # Set time before trying to commit
        db.session.commit()
        committed_items_count = len(items_to_add)
        logger.info(
            "Successfully batch-added %s new items for feed: %s",
            committed_items_count,
            feed_db_obj.name,
        )
    except IntegrityError as e:
        db.session.rollback()  # Rollback the failed batch
        logger.warning(
            "Batch insert failed for feed '%s' due to IntegrityError: %s. Attempting individual inserts.",
            feed_db_obj.name,
            e,
        )

        # Ensure last_updated_time is set even if all individual inserts fail,
        # as the feed itself was successfully fetched and processed up to this point.
        # This needs to be part of a new transaction if the previous one was rolled back.
        try:
            feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
            # Re-add if it became detached after rollback
            db.session.add(feed_db_obj)
            db.session.commit()
        except Exception as ts_e:
            db.session.rollback()
            logger.error(
                "Error updating last_updated_time for feed '%s' after batch insert failure: %s",
                feed_db_obj.name,
                ts_e,
                exc_info=True,
            )

        for item_to_add in items_to_add:
            try:
                # Each item needs to be added to a fresh session or re-added if the session was rolled back.
                # If items were expunged by rollback, they might need to be re-created or merged.
                # Simplest is to re-add to current session if it's still active for individual commits.
                db.session.add(item_to_add)  # Re-add the item to the session
                db.session.commit()
                committed_items_count += 1
                logger.debug(
                    "Individually added item: %s for feed '%s'",
                    item_to_add.title[:50],
                    feed_db_obj.name,
                )
            except IntegrityError as ie_individual:
                db.session.rollback()  # Rollback this specific item's commit
                logger.error(
                    "Failed to individually add item '%s' (link: %s, guid: %s) for feed '%s': %s",
                    item_to_add.title[:100],
                    item_to_add.link,
                    item_to_add.guid,
                    feed_db_obj.name,
                    ie_individual,
                    exc_info=False,
                )  # Log less verbosely for individual fails
            except Exception as e_individual:
                db.session.rollback()
                logger.error(
                    "Generic error individually adding item '%s' for feed '%s': %s",
                    item_to_add.title[:100],
                    feed_db_obj.name,
                    e_individual,
                    exc_info=True,
                )

        if committed_items_count > 0:
            logger.info(
                "Successfully added %s items individually for feed: %s after batch failure.",
                committed_items_count,
                feed_db_obj.name,
            )
        else:
            logger.info(
                "No items could be added individually for feed: %s after batch failure.",
                feed_db_obj.name,
            )

    except Exception as e:
        db.session.rollback()
        logger.error(
            "Generic error committing new items for feed %s: %s",
            feed_db_obj.name,
            e,
            exc_info=True,
        )
        return 0  # Return 0 as no items were successfully committed in this case

    # --- Cache Eviction Logic ---
    # After adding new items, check if the total number of items exceeds the limit.
    # If so, delete the oldest items to keep the total at the limit.
    current_item_count = (
        db.session.query(FeedItem).filter_by(feed_id=feed_db_obj.id).count()
    )

    if current_item_count > MAX_ITEMS_PER_FEED:
        num_to_delete = current_item_count - MAX_ITEMS_PER_FEED

        # Use a subquery to find and delete the oldest items in a single operation.
        # This is more efficient than fetching IDs into application memory.
        oldest_item_ids_q = (
            db.session.query(FeedItem.id)
            .filter_by(feed_id=feed_db_obj.id)
            .order_by(FeedItem.published_time.asc(), FeedItem.fetched_time.asc())
            .limit(num_to_delete)
        )

        # The `delete()` method returns the number of rows deleted.
        deleted_count = (
            db.session.query(FeedItem)
            .filter(FeedItem.id.in_(oldest_item_ids_q))
            .delete(synchronize_session=False)
        )

        if deleted_count > 0:
            logger.info(
                "Evicted %s oldest items from feed '%s' to enforce item limit.",
                deleted_count,
                feed_db_obj.name,
            )
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(
                    "Error committing eviction of old items for feed '%s': %s",
                    feed_db_obj.name,
                    e,
                    exc_info=True,
                )

    return committed_items_count


def fetch_and_update_feed(feed_id):
    """Fetches a single feed by ID, processes its entries, and updates the database.

    Args:
        feed_id (int): The database ID of the Feed to update.

    Returns:
        A tuple (success, new_items_count, tab_id):
        - success (bool): True if the feed was fetched and processed successfully (even if 0 new items), False otherwise.
        - new_items_count (int): The number of new items added.
        - tab_id (int): The ID of the tab this feed belongs to.
    """
    feed = db.session.get(Feed, feed_id)
    if not feed:
        logger.error("Feed with ID %s not found for update.", feed_id)
        return False, 0, None

    # fetch_feed already handles errors and returns None, but logic here checks return
    parsed_feed = fetch_feed(feed.url)

    # Delegate processing to helper
    return _process_fetch_result(feed, parsed_feed)


def update_all_feeds():
    """Iterates through all feeds in the database, fetches updates in parallel, and processes entries.

    Returns:
        A tuple (total_feeds_processed_successfully, total_new_items, affected_tab_ids):
        - total_feeds_processed_successfully (int): Number of feeds where fetch and process stages completed without critical failure.
        - total_new_items (int): Total new items added across all feeds.
        - affected_tab_ids (set): A set of tab IDs that received new items.
    """
    all_feeds = Feed.query.all()
    total_new_items = 0
    attempted_count = 0
    processed_successfully_count = 0
    affected_tab_ids = set()

    # Map feed_id to feed object for easy access during processing
    feeds_by_id = {feed.id: feed for feed in all_feeds}

    logger.info(
        "Starting update process for %s feeds (Parallelized).", len(all_feeds))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_CONCURRENT_FETCHES
    ) as executor:
        # Submit all fetch tasks
        future_to_feed_id = {
            executor.submit(_fetch_feed_content, feed.id, feed.url): feed.id
            for feed in all_feeds
        }
        attempted_count = len(all_feeds)

        for future in concurrent.futures.as_completed(future_to_feed_id):
            feed_id = future_to_feed_id[future]
            feed_obj = feeds_by_id.get(feed_id)

            if not feed_obj:
                # Should not happen given current logic, but safe guard
                logger.error(
                    "Feed ID %s not found in mapping during processing.", feed_id
                )
                continue

            logger.info(
                "Processing result for feed: %s (%s)",
                feed_obj.name,
                feed_obj.id,
            )

            try:
                # Retrieve result from the thread
                _, parsed_feed = future.result()

                # --- Sequential Processing (Main Thread) ---
                # Check 1: Reuse the logic shared with fetch_and_update_feed
                success, new_items, tab_id = _process_fetch_result(
                    feed_obj, parsed_feed
                )

                if success:
                    processed_successfully_count += 1
                    total_new_items += new_items
                    if new_items > 0:
                        affected_tab_ids.add(tab_id)

            except Exception as e:
                logger.error(
                    "Unexpected critical error processing future for feed %s (%s): %s",
                    feed_obj.name,
                    feed_id,
                    e,
                    exc_info=True,
                )
                continue

    logger.info(
        "Finished updating feeds. Attempted: %s, Successfully Processed: %s, Total New Items Added: %s",
        attempted_count,
        processed_successfully_count,
        total_new_items,
    )
    return processed_successfully_count, total_new_items, affected_tab_ids
