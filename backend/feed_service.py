"""Service module for fetching, parsing, and processing RSS/Atom feeds."""

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
from xml.sax import SAXParseException
from xml.sax.handler import ContentHandler

import defusedxml.sax
import feedparser
from dateutil import parser as date_parser
from defusedxml.common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)
from sqlalchemy.exc import IntegrityError

# Import database models from the new models.py
from .models import Feed, FeedItem, db

# Set up logger for this module
logger = logging.getLogger(__name__)

# Maximum number of items to keep per feed for cache eviction
MAX_ITEMS_PER_FEED = 100

# Hard cap for concurrent fetches to avoid resource exhaustion
# 20 is suitable for typical small VPS instances (e.g., 4 vCPUs) handling I/O bound tasks
WORKER_FETCH_CAP = 20


# Maximum number of concurrent feed fetches
# I/O bound tasks can handle more workers than CPU cores
def _get_max_concurrent_fetches():
    """Calculates the maximum number of concurrent feed fetches.

    Returns:
        int: The maximum number of concurrent fetches.
    """
    try:
        cpu_count = os.cpu_count() or 1
    except (NotImplementedError, OSError):
        cpu_count = 1

    try:
        max_workers = int(os.environ.get("FEED_FETCH_MAX_WORKERS", 0))
    except (ValueError, TypeError):
        max_workers = 0

    if max_workers <= 0:
        # Default heuristic with safety cap for auto-configuration
        return min(cpu_count * 5, WORKER_FETCH_CAP)

    # Respect explicit user configuration, but enforce the hard cap
    return min(max_workers, WORKER_FETCH_CAP)


MAX_CONCURRENT_FETCHES = _get_max_concurrent_fetches()

# --- Helper Functions ---


def _validate_xml_safety(content):
    """
    Validates XML content for XXE vulnerabilities using defusedxml.
    Returns False if a security violation is detected.
    Returns True if the content is safe (or not XML, or malformed in a non-dangerous way).

    Policy:
    - forbid_dtd=False: We allow DTDs generally (e.g. for internal entities or standard RSS).
    - forbid_entities=True: We STRICTLY block custom entity declarations (XXE vector).
    - forbid_external=True: We STRICTLY block external DTDs/Entities (SSRF vector).
    """
    try:
        # We use a no-op handler because we only care about the parsing process raising security exceptions
        handler = ContentHandler()
        defusedxml.sax.parseString(
            content,
            handler,
            forbid_dtd=False,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden) as e:
        logger.error("XML Security Violation detected: %s", e)
        return False
    except (SAXParseException, UnicodeError):
        # Other exceptions (like SAXParseException, encoding errors, etc.)
        # are ignored here because we want to allow feedparser to try its best
        # with potentially malformed but non-malicious content (e.g. HTML soup).
        pass

    return True


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
    pub_parsed = getattr(entry, "published_parsed", None)
    if isinstance(pub_parsed, (list, tuple)) and len(pub_parsed) >= 6:
        try:
            parsed_dt = datetime.datetime(*pub_parsed[:6], tzinfo=timezone.utc)
        except (TypeError, ValueError):
            parsed_dt = None

    if parsed_dt is None:
        # Try common date fields using dateutil.parser
        for field in ["published", "updated", "created", "dc:date"]:
            parsed_dt = _get_dt_from_field(entry, field)
            if isinstance(parsed_dt, datetime.datetime):
                break
            parsed_dt = None

    if isinstance(parsed_dt, datetime.datetime):
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(
                parsed_dt) is None:
            return parsed_dt.replace(tzinfo=timezone.utc)
        return parsed_dt.astimezone(timezone.utc)

    return datetime.datetime.now(timezone.utc)


def _get_dt_from_field(entry, field):
    """Internal helper to extract a datetime from a specific entry field."""
    if not hasattr(entry, field):
        return None
    field_value = getattr(entry, field)
    if not field_value:
        return None
    try:
        return date_parser.parse(field_value)
    except (ValueError, TypeError, OverflowError):
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


# --- Core Feed Processing Functions ---


def validate_and_resolve_url(url):
    """Validates URL and resolves IP to prevent SSRF (returns safe IP or None)."""
    try:
        parsed = urlparse(url)
        if not (parsed.scheme in ("http", "https") and parsed.hostname):
            return None, None

        try:
            addr_info = socket.getaddrinfo(parsed.hostname, None)
        except socket.gaierror:
            if os.environ.get("TESTING") == "true":
                return ("127.0.0.1", parsed.hostname)
            return (None, None)

        for res in addr_info:
            ip_str = res[4][0]
            ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
            if _is_safe_ip(ip_obj):
                return ip_str, parsed.hostname

            logger.warning(
                "Blocked SSRF attempt: %s://%s -> %s",
                parsed.scheme,
                parsed.hostname,
                ip_obj,
            )

        return (None, None)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error validating URL safety")
        return (None, None)


def _is_safe_ip(ip):
    """Checks if an IP address is safe (not private, loopback, etc.)."""
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _fetch_feed_content(feed_url):
    """Fetches and parses feed content from a given URL.

    This function is a wrapper around `fetch_feed` to handle exceptions
    when used in concurrent execution contexts. It is designed to be
    side-effect-free regarding the database.

    Args:
        feed_url (str): The URL of the feed to fetch.

    Returns:
        feedparser.FeedParserDict | None: The parsed feed object, or None if
        fetching or parsing failed.
    """
    try:
        parsed_feed = fetch_feed(feed_url)
        return parsed_feed
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error in fetch thread for feed %s", feed_url)
        return None


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
        except Exception:  # pylint: disable=broad-exception-caught
            db.session.rollback()
            logger.error(
                "Error committing feed update (no entries) for %s",
                feed_db_obj.name,
                exc_info=True,
            )
            # Still, the fetch itself might be considered a "success" in terms of reachability
        return True, 0, feed_db_obj.tab_id

    try:
        new_items = process_feed_entries(feed_db_obj, parsed_feed)
        # process_feed_entries handles its own logging and commits for items and last_updated_time.
        return True, new_items, feed_db_obj.tab_id
    except Exception:  # pylint: disable=broad-exception-caught
        logger.error(
            "An unexpected error occurred during entry processing for feed '%s' (ID: %s)",
            feed_db_obj.name,
            feed_db_obj.id,
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

        req = urllib.request.Request(target_url,
                                     headers={
                                         "Host": hostname,
                                         "User-Agent": "SheepVibes/1.0"
                                     })
        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
            # Limit response size to 10MB to prevent DoS/OOM
            content = response.read(10 * 1024 * 1024)

        if not _validate_xml_safety(content):
            # Sanitize URL for logging to prevent log injection
            safe_log_url = feed_url.replace("\n", "\\n").replace("\r", "\\r")
            logger.warning("Feed rejected due to security violation: %s",
                           safe_log_url)
            return None

        parsed_feed = feedparser.parse(content)
        # feedparser.parse(bytes) doesn't set bozo for network errors, but we handled network above.
        if parsed_feed.bozo:
            logger.warning("Feed parsing warning: %s",
                           parsed_feed.get("bozo_exception"))

        return parsed_feed

    except Exception:  # pylint: disable=broad-exception-caught
        logger.error("Error fetching feed %s", feed_url, exc_info=True)
        return None


# --- Feed Processing Helpers ---


def _update_feed_metadata(feed_db_obj, parsed_feed):
    """Updates feed title and site_link if changed.

    Args:
        feed_db_obj (Feed): The database feed object.
        parsed_feed (feedparser.FeedParserDict): The parsed feed result.
    """
    raw_title = parsed_feed.feed.get("title")
    new_title = raw_title.strip() if raw_title else None
    if new_title and new_title != feed_db_obj.name:
        logger.info("Updating feed title for '%s' to '%s'", feed_db_obj.name,
                    new_title)
        feed_db_obj.name = new_title

    raw_site_link = parsed_feed.feed.get("link")
    new_site_link = raw_site_link.strip() if raw_site_link else None
    if new_site_link and new_site_link != feed_db_obj.site_link:
        logger.info(
            "Updating feed site_link for '%s' from '%s' to '%s'",
            feed_db_obj.name,
            feed_db_obj.site_link,
            new_site_link,
        )
        feed_db_obj.site_link = new_site_link


def _collect_new_items(feed_db_obj, parsed_feed):
    """Identifies new items to add and updates existing ones."""
    items_to_add = []
    batch_processed_guids = set()
    batch_processed_links = set()

    # Optimization: Query only necessary columns to avoid loading full objects
    # item[1] is guid, item[2] is link, item[3] is title
    items_tuple = (db.session.query(
        FeedItem.id, FeedItem.guid, FeedItem.link,
        FeedItem.title).filter_by(feed_id=feed_db_obj.id).all())

    # Create lookup maps
    existing_items_by_guid = {it.guid: it for it in items_tuple if it.guid}
    existing_items_by_link = {it.link: it for it in items_tuple if it.link}

    logger.info(
        "Processing %s entries for feed: %s (ID: %s)",
        len(parsed_feed.entries),
        feed_db_obj.name,
        feed_db_obj.id,
    )

    # Pre-calculate dates to avoid double parsing and ensure consistency between
    # sorting and storage (e.g. if parse_published_time uses current time as fallback).
    entries_with_dates = []
    for entry in parsed_feed.entries:
        entries_with_dates.append((entry, parse_published_time(entry)))

    # Sort entries by published date (newest first).
    # Our "First Wins" deduplication strategy (below) will preserve the version
    # that appears first in the iteration. Sorting ensures the most recently
    # published version is processed first and thus preserved in case of duplicates.
    try:
        entries_with_dates.sort(key=lambda x: x[1], reverse=True)
    except Exception:  # pylint: disable=broad-exception-caught
        # If sorting fails, proceed with original order.
        logger.warning("Failed to sort entries for feed %s", feed_db_obj.name)

    for entry, parsed_published in entries_with_dates:
        entry_link = entry.get("link")

        if not entry_link:
            logger.warning(
                "Skipping entry titled '%s' for feed '%s' due to missing link.",
                entry.get("title", "[No Title]")[:100],
                feed_db_obj.name,
            )
            continue

        db_guid = entry.get("id") or entry_link

        # Check existing
        existing_match = existing_items_by_guid.get(db_guid)
        if not existing_match:
            existing_match = existing_items_by_link.get(entry_link)

        if existing_match:
            _update_existing_item(
                feed_db_obj,
                existing_match,
                entry.get("title", "[No Title]"),
                entry_link,
            )
            continue

        # Check batch duplicates
        if _is_batch_duplicate(
                db_guid,
                entry_link,
                batch_processed_guids,
                batch_processed_links,
                feed_db_obj.name,
        ):
            continue

        if db_guid:
            batch_processed_guids.add(db_guid)
        batch_processed_links.add(entry_link)

        items_to_add.append(
            FeedItem(
                feed_id=feed_db_obj.id,
                title=entry.get("title", "[No Title]"),
                link=entry_link,
                published_time=parsed_published,
                guid=db_guid,
            ))

    return items_to_add


def _update_existing_item(feed_db_obj, existing_item_data, entry_title,
                          entry_link):
    """Updates an existing item if title or link changed.

    Args:
        feed_db_obj (Feed): The database feed object.
        existing_item_data (Row): Tuple-like object with existing item ID, title, and link.
        entry_title (str): New title from the feed entry.
        entry_link (str): New link from the feed entry.
    """
    existing_title = existing_item_data.title
    existing_link = existing_item_data.link

    updates = {}
    if entry_title and entry_title != existing_title:
        updates["title"] = entry_title

    if entry_link and entry_link != existing_link:
        updates["link"] = entry_link

    if updates:
        logger.info(
            "Updating fields %s for existing item '%s' in feed '%s'",
            list(updates.keys()),
            existing_title,
            feed_db_obj.name,
        )
        db.session.query(FeedItem).filter(
            FeedItem.id == existing_item_data.id).update(
                updates, synchronize_session=False)


def _is_batch_duplicate(db_guid, entry_link, batch_guids, batch_links,
                        feed_name):
    """Checks if an item is a duplicate within the current processing batch.

    Args:
        db_guid (str): Calculated GUID for the item.
        entry_link (str): Link for the item.
        batch_guids (set): Set of GUIDs processed in current batch.
        batch_links (set): Set of links processed in current batch.
        feed_name (str): Name of the feed for logging.

    Returns:
        bool: True if it's a duplicate, False otherwise.
    """
    if db_guid and db_guid in batch_guids:
        logger.warning(
            "Skipping duplicate item (GUID: %s) in batch for feed '%s'.",
            db_guid,
            feed_name,
        )
        return True
    if entry_link in batch_links:
        logger.warning(
            "Skipping duplicate item (Link: %s) in batch for feed '%s'.",
            entry_link,
            feed_name,
        )
        return True
    return False


def _save_items_to_db(feed_db_obj, items_to_add):
    """Commits new items to the database, handling batch failures."""
    committed_count = 0
    try:
        db.session.add_all(items_to_add)
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        db.session.commit()
        committed_count = len(items_to_add)
        logger.info(
            "Successfully batch-added %s new items for feed: %s",
            committed_count,
            feed_db_obj.name,
        )
    except IntegrityError as e:
        db.session.rollback()
        logger.warning(
            "Batch insert failed for feed '%s': %s. Retrying individually.",
            feed_db_obj.name,
            e,
        )
        committed_count = _save_items_individually(feed_db_obj, items_to_add)
    except Exception:  # pylint: disable=broad-exception-caught
        db.session.rollback()
        logger.error(
            "Generic error committing new items for feed %s",
            feed_db_obj.name,
            exc_info=True,
        )
        return 0

    return committed_count


def _save_items_individually(feed_db_obj, items_to_add):
    """Helper to save items one by one after a batch failure."""
    # Ensure last_updated_time is updated even if items fail
    try:
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        db.session.add(feed_db_obj)
        db.session.commit()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.error(
            "Error updating last_updated_time for feed '%s' after batch failure",
            feed_db_obj.name,
            exc_info=True,
        )
        db.session.rollback()  # Rollback if updating last_updated_time fails

    count = 0
    for item in items_to_add:
        try:
            db.session.add(item)
            db.session.commit()
            count += 1
            logger.debug("Individually added item: %s", item.title[:50])
        except IntegrityError as ie:
            db.session.rollback()
            logger.error(
                "Failed to add item '%s' for feed '%s' (link: %s, guid: %s): %s",
                item.title[:100],
                feed_db_obj.name,
                item.link,
                item.guid,
                ie,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            db.session.rollback()
            logger.error("Generic error adding item '%s'",
                         item.title[:100],
                         exc_info=True)

    if count > 0:
        logger.info("Recovered %s items individually for feed: %s", count,
                    feed_db_obj.name)
    else:
        logger.info("No items added individually for feed: %s",
                    feed_db_obj.name)

    return count


def _enforce_feed_limit(feed_db_obj):
    """Enforces MAX_ITEMS_PER_FEED by evicting oldest items."""
    current_count = db.session.query(FeedItem).filter_by(
        feed_id=feed_db_obj.id).count()
    if current_count <= MAX_ITEMS_PER_FEED:
        return

    num_to_delete = current_count - MAX_ITEMS_PER_FEED
    # Use a subquery construct for efficient deletion.
    # Note: SQLite has limitations with simultaneous read/write in subqueries for DELETE.
    # We fetch IDs first which is safer across DBs for this logic.
    # Actually, the previous implementation was:
    # oldest_ids = query.limit().all() -> delete(id.in_(oldest_ids))
    # Qodo said: "Consider converting to a scalar subquery...".
    # Let's clean up the implementation to use a subquery construct properly.
    # The previous code was:
    # oldest_ids = ( ... .limit(num_to_delete) )  <-- This is a Query object
    # .filter(FeedItem.id.in_(oldest_ids))
    # It failed to call .all() or .subquery()! It passed the raw Query object to in_().
    # THAT is the bug/inefficiency.

    oldest_ids = (db.session.query(
        FeedItem.id).filter_by(feed_id=feed_db_obj.id).order_by(
            FeedItem.published_time.asc(),
            FeedItem.fetched_time.asc()).limit(num_to_delete).all())

    # Flatten the list of tuples
    oldest_ids_list = [r.id for r in oldest_ids]

    if not oldest_ids_list:
        return

    deleted_count = (db.session.query(FeedItem).filter(
        FeedItem.id.in_(oldest_ids_list)).delete(synchronize_session=False))

    if deleted_count > 0:
        logger.info("Evicted %s oldest items from feed '%s'.", deleted_count,
                    feed_db_obj.name)
        try:
            db.session.commit()
        except Exception:  # pylint: disable=broad-exception-caught
            db.session.rollback()
            logger.error(
                "Error committing eviction for feed '%s'",
                feed_db_obj.name,
                exc_info=True,
            )


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

    _update_feed_metadata(feed_db_obj, parsed_feed)
    items_to_add = _collect_new_items(feed_db_obj, parsed_feed)

    # Commit metadata and existing item updates immediately.
    # This ensures they are preserved even if the batch insert of new items fails later.
    try:
        db.session.commit()
    except Exception:  # pylint: disable=broad-exception-caught
        db.session.rollback()
        logger.error(
            "Error committing metadata/existing items for feed %s",
            feed_db_obj.name,
            exc_info=True,
        )
        # It's safer to stop processing this feed to avoid potential inconsistencies
        # if the metadata/update commit failed.
        return 0

    if not items_to_add:
        # If no new items, we are done.
        # last_updated_time is usually updated on successful commit of items,
        # or here if there were no items but fetch succeeded.
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception:  # pylint: disable=broad-exception-caught
            db.session.rollback()
            logger.error(
                "Error committing feed update (no new items) for %s",
                feed_db_obj.name,
                exc_info=True,
            )
        return 0

    committed_items_count = _save_items_to_db(feed_db_obj, items_to_add)
    _enforce_feed_limit(feed_db_obj)

    return committed_items_count


def fetch_and_update_feed(feed_id):
    """Fetches a single feed by ID and updates the database.

    Args:
        feed_id (int): The database ID of the Feed to update.

    Returns:
        tuple (bool, int, int): (success, new_items_count, tab_id)
    """
    feed = db.session.get(Feed, feed_id)
    if not feed:
        logger.error("Feed with ID %s not found for update.", feed_id)
        return False, 0, None

    # fetch_feed already handles errors and returns None, but logic here checks return
    parsed_feed = _fetch_feed_content(feed.url)

    # Delegate processing to helper
    return _process_fetch_result(feed, parsed_feed)


def update_all_feeds():
    """Fetches all feeds in parallel and processes entries.

    Returns:
        tuple (int, int, set): (success_count, total_new_items, affected_tab_ids)
    """
    all_feeds = Feed.query.all()
    total_new_items = 0
    attempted_count = 0
    processed_successfully_count = 0
    affected_tab_ids = set()

    logger.info("Starting update process for %s feeds (Parallelized).",
                len(all_feeds))

    # Optimize workers: don't create more threads than actual feeds
    actual_workers = min(MAX_CONCURRENT_FETCHES,
                         len(all_feeds)) if all_feeds else 1

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=actual_workers) as executor:
        # Submit all fetch tasks, mapping future to the feed object directly
        future_to_feed = {
            executor.submit(_fetch_feed_content, feed.url): feed
            for feed in all_feeds
        }
        attempted_count = len(all_feeds)

        for future in concurrent.futures.as_completed(future_to_feed):
            feed_obj = future_to_feed[future]
            feed_id = feed_obj.id

            logger.info(
                "Processing result for feed: %s (%s)",
                feed_obj.name,
                feed_id,
            )

            try:
                # Retrieve result from the thread
                parsed_feed = future.result()

                # --- Sequential Processing (Main Thread) ---
                # Check 1: Reuse the logic shared with fetch_and_update_feed
                success, new_items, tab_id = _process_fetch_result(
                    feed_obj, parsed_feed)

                if success:
                    processed_successfully_count += 1
                    total_new_items += new_items
                    if new_items > 0:
                        affected_tab_ids.add(tab_id)

            except Exception:  # pylint: disable=broad-exception-caught
                logger.error(
                    "Unexpected critical error processing future for feed %s (%s)",
                    feed_obj.name,
                    feed_id,
                    exc_info=True,
                )
                continue

    logger.info(
        "Finished updating feeds. Attempted: %s, Success: %s, New Items: %s",
        attempted_count,
        processed_successfully_count,
        total_new_items,
    )
    return processed_successfully_count, total_new_items, affected_tab_ids
