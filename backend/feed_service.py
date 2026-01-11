# Import necessary libraries
import feedparser
import datetime # Import the full module
from datetime import timezone # Specifically import timezone
import logging # Standard logging
import ssl # Added for specific SSL error catching
import concurrent.futures # Added for parallel execution
import os # Added for environment variables
from collections import defaultdict # Added for grouping feeds by URL
import socket
import ipaddress
from urllib.parse import urlparse
from dateutil import parser as date_parser # Use dateutil for robust date parsing
from sqlalchemy.exc import IntegrityError
import requests # Added for robust fetching with timeouts

# Import database models from the new models.py
from .models import db, Feed, FeedItem

# Set up logger for this module
logger = logging.getLogger(__name__)

# Maximum number of items to keep per feed for cache eviction
MAX_ITEMS_PER_FEED = 100

# --- Helper Functions ---

def _get_env_int(var_name, default_value):
    """
    Retrieves an environment variable as an integer, falling back to a default
    if the variable is not set or is not a valid integer.
    Also ensures the value is positive.

    Args:
        var_name (str): The name of the environment variable.
        default_value (int): The default value to return.

    Returns:
        int: The parsed integer value or the default.
    """
    try:
        value = int(os.environ.get(var_name, default_value))
        if value <= 0:
            logger.warning(f"Invalid non-positive value for {var_name}. Defaulting to {default_value}.")
            return default_value
        return value
    except ValueError:
        logger.warning(f"Invalid value for {var_name}. Defaulting to {default_value}.")
        return default_value

# Configuration constants
FEED_FETCH_MAX_WORKERS = _get_env_int("FEED_FETCH_MAX_WORKERS", 10)
FEED_FETCH_TIMEOUT = _get_env_int("FEED_FETCH_TIMEOUT", 30)

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
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        try:
            parsed_dt = datetime.datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except (TypeError, ValueError) as e:
            logger.debug(f"Failed to parse 'published_parsed' for entry {entry.get('link', '[no link]')}: {e}")
            parsed_dt = None
    
    if parsed_dt is None:
        # Try common date fields using dateutil.parser for more flexibility
        # Added 'dc:date' as observed in some feeds
        date_fields = ['published', 'updated', 'created', 'dc:date']
        for field in date_fields:
            if hasattr(entry, field):
                field_value = getattr(entry, field)
                if field_value:
                    try:
                        parsed_dt = date_parser.parse(field_value)
                        if parsed_dt:
                            break
                    except (ValueError, TypeError, OverflowError) as e:
                        logger.debug(f"Specific parsing error for date field '{field}' for entry {entry.get('link', '[no link]')} ({type(e).__name__}): {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Generic parsing error for date field '{field}' for entry {entry.get('link', '[no link]')} ({type(e).__name__}): {e}")
                        continue

    if parsed_dt:
        # Ensure the datetime is UTC timezone-aware
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        else:
            parsed_dt = parsed_dt.astimezone(timezone.utc)
        return parsed_dt
                
    logger.warning(f"Could not parse published time for entry: {entry.get('link', '[no link]')}. Using current time as fallback.")
    return datetime.datetime.now(timezone.utc)

def validate_and_resolve_url(url):
    """Validates URL and resolves IP to prevent SSRF (returns safe IP or None)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            logger.warning(f"Blocked unsupported URL scheme: {parsed.scheme}")
            return None, None

        hostname = parsed.hostname
        if not hostname:
            return None, None

        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            if os.environ.get('TESTING') == 'true':
                 return '127.0.0.1', hostname # Fallback for tests
            logger.warning(f"Could not resolve hostname: {hostname}")
            return None, None

        safe_ip = None
        for res in addr_info:
            ip_str = res[4][0]
            clean_ip_str = ip_str.split('%')[0]
            try:
                ip = ipaddress.ip_address(clean_ip_str)
                if (ip.is_private or ip.is_loopback or ip.is_link_local or
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                    safe_url = f"{parsed.scheme}://{hostname}"
                    logger.warning(f"Blocked SSRF attempt: {safe_url} -> {ip}")
                    return None, None
                safe_ip = ip_str # Keep valid IP string
                break # Found a safe IP
            except ValueError:
                continue

        return safe_ip, hostname
    except Exception:
        logger.exception("Error validating URL safety")
        return None, None

# --- Core Feed Processing Functions ---

def fetch_feed(feed_url):
    """Fetches and parses a feed using requests and feedparser, preventing SSRF."""
    safe_ip, hostname = validate_and_resolve_url(feed_url)
    if not safe_ip:
        return None

    logger.info(f"Fetching feed: {feed_url}")
    try:
        # Prevent TOCTOU: Fetch using the validated IP
        parsed = urlparse(feed_url)

        # Only rewrite URL for HTTP to avoid SSL hostname mismatch
        # For HTTPS, we accept the risk of DNS rebinding between check and fetch for now
        # to ensure SSL validation passes without complex custom adapters.
        if parsed.scheme == 'http':
            # Reconstruct URL using safe_ip as the netloc (host)
            # This ensures we connect to the IP we validated
            target_url = parsed._replace(netloc=safe_ip).geturl()
            headers = {'Host': hostname, 'User-Agent': 'SheepVibes/1.0'}
        else:
            target_url = feed_url
            headers = {'User-Agent': 'SheepVibes/1.0'}

        # Use requests to fetch content with a timeout, avoiding thread-blocking issues
        response = requests.get(target_url, headers=headers, timeout=FEED_FETCH_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx, 5xx)

        # Parse the content directly
        parsed_feed = feedparser.parse(response.content)
        
        if parsed_feed.bozo:
            bozo_exc = parsed_feed.get('bozo_exception', Exception('Unknown parsing error (bozo=1)'))
            error_message = str(bozo_exc)

            if "SSL" in error_message.upper() or \
               "CERTIFICATE" in error_message.upper() or \
               isinstance(bozo_exc, ssl.SSLError):
                logger.error(
                    f"Failed to fetch feed {feed_url} due to SSL/Certificate error (feedparser bozo): {error_message}",
                    exc_info=False
                )
            else:
                logger.warning(f"Feed is ill-formed: {feed_url} - Error: {error_message}")

        if not parsed_feed.entries and not parsed_feed.bozo:
             logger.warning(f"No entries found in feed (and not a bozo feed): {feed_url}")

        if not parsed_feed.bozo:
            logger.info(f"Successfully fetched feed: {feed_url}")
        return parsed_feed

    except requests.exceptions.RequestException as req_e:
        logger.error(f"Network error fetching feed {feed_url}: {req_e}")
        return None
    except ssl.SSLError as ssl_e:
        logger.error(f"Direct SSL Error during fetch attempt for {feed_url}: {ssl_e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Generic error fetching or parsing feed {feed_url}: {e}", exc_info=True)
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
        logger.error(f"process_feed_entries called with a null parsed_feed for feed ID {feed_db_obj.id if feed_db_obj else 'Unknown'}")
        return 0

    # These sets track items *within the current batch being processed*
    batch_processed_links = set()

    # Get existing GUIDs and links *for this specific feed* from the DB
    existing_feed_items_query = db.session.query(FeedItem.guid, FeedItem.link).filter_by(feed_id=feed_db_obj.id)
    # Ensure we only add non-None GUIDs to the set
    existing_feed_guids = {item.guid for item in existing_feed_items_query if item.guid}
    # Ensure we only add non-None links to the set (though link is NOT NULL in DB)
    existing_feed_links = {item.link for item in existing_feed_items_query if item.link}


    new_title = parsed_feed.feed.get('title')
    if new_title and new_title.strip() and new_title != feed_db_obj.name:
        logger.info(f"Updating feed title for '{feed_db_obj.name}' to '{new_title}'")
        feed_db_obj.name = new_title

    # Update site_link if available and different
    new_site_link = parsed_feed.feed.get('link') # This is typically the website link
    if new_site_link and new_site_link.strip() and new_site_link != feed_db_obj.site_link:
        logger.info(f"Updating feed site_link for '{feed_db_obj.name}' from '{feed_db_obj.site_link}' to '{new_site_link}'")
        feed_db_obj.site_link = new_site_link
    elif not feed_db_obj.site_link and new_site_link and new_site_link.strip(): # If current is null, set it
        logger.info(f"Setting feed site_link for '{feed_db_obj.name}' to '{new_site_link}'")
        feed_db_obj.site_link = new_site_link


    logger.info(f"Processing {len(parsed_feed.entries)} entries for feed: {feed_db_obj.name} (ID: {feed_db_obj.id})")

    items_to_add = []

    for entry in parsed_feed.entries:
        entry_title = entry.get('title', '[No Title]')
        entry_link = entry.get('link')
        feedparser_id = entry.get('id') # This is what feedparser provides as 'id'

        if not entry_link: # Link is essential
            logger.warning(f"Skipping entry titled '{entry_title[:100]}' for feed '{feed_db_obj.name}' due to missing link. (feedparser ID: {feedparser_id if feedparser_id else 'N/A'})")
            continue

        # Determine the GUID to be stored in the database (db_guid).
        db_guid = entry_link

        # --- Deduplication Logic ---
        # 1. Check against items already in the DB *for this specific feed*
        if (db_guid and db_guid in existing_feed_guids) or (entry_link in existing_feed_links):
            continue

        # 2. Check against items already processed *in this current batch*
        if entry_link in batch_processed_links:
            logger.warning(f"Skipping duplicate item in current batch (link: {entry_link}) for feed '{feed_db_obj.name}'.")
            continue

        # If we reach here, the item is considered new.
        batch_processed_links.add(entry_link)

        published_time = parse_published_time(entry) # Already falls back to now()

        new_item = FeedItem(
            feed_id=feed_db_obj.id,
            title=entry_title,
            link=entry_link,
            published_time=published_time,
            guid=db_guid
        )
        items_to_add.append(new_item)

    if not items_to_add:
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit() # Commit to save updated last_updated_time
        except Exception as e: # Catch potential errors during this commit
            db.session.rollback()
            logger.error(f"Error committing feed update (no new items) for {feed_db_obj.name}: {e}", exc_info=True)
        return 0

    committed_items_count = 0
    try:
        db.session.add_all(items_to_add)
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc) # Set time before trying to commit
        db.session.commit()
        committed_items_count = len(items_to_add)
        logger.info(f"Successfully batch-added {committed_items_count} new items for feed: {feed_db_obj.name}")
    except IntegrityError as e:
        db.session.rollback() # Rollback the failed batch
        logger.warning(f"Batch insert failed for feed '{feed_db_obj.name}' due to IntegrityError: {e}. Attempting individual inserts.")

        try:
            feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
            db.session.add(feed_db_obj) # Re-add if it became detached after rollback
            db.session.commit()
        except Exception as ts_e:
            db.session.rollback()
            logger.error(f"Error updating last_updated_time for feed '{feed_db_obj.name}' after batch insert failure: {ts_e}", exc_info=True)

        for item_to_add in items_to_add:
            try:
                db.session.add(item_to_add) # Re-add the item to the session
                db.session.commit()
                committed_items_count += 1
                logger.debug(f"Individually added item: {item_to_add.title[:50]} for feed '{feed_db_obj.name}'")
            except IntegrityError as ie_individual:
                db.session.rollback() # Rollback this specific item's commit
                logger.error(f"Failed to individually add item '{item_to_add.title[:100]}' (link: {item_to_add.link}, guid: {item_to_add.guid}) for feed '{feed_db_obj.name}': {ie_individual}", exc_info=False) # Log less verbosely for individual fails
            except Exception as e_individual:
                db.session.rollback()
                logger.error(f"Generic error individually adding item '{item_to_add.title[:100]}' for feed '{feed_db_obj.name}': {e_individual}", exc_info=True)

        if committed_items_count > 0:
            logger.info(f"Successfully added {committed_items_count} items individually for feed: {feed_db_obj.name} after batch failure.")
        else:
            logger.info(f"No items could be added individually for feed: {feed_db_obj.name} after batch failure.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Generic error committing new items for feed {feed_db_obj.name}: {e}", exc_info=True)
        return 0 # Return 0 as no items were successfully committed in this case

    # --- Cache Eviction Logic ---
    current_item_count = db.session.query(FeedItem).filter_by(feed_id=feed_db_obj.id).count()

    if current_item_count > MAX_ITEMS_PER_FEED:
        num_to_delete = current_item_count - MAX_ITEMS_PER_FEED
        
        oldest_item_ids_q = (
            db.session.query(FeedItem.id)
            .filter_by(feed_id=feed_db_obj.id)
            .order_by(FeedItem.published_time.asc(), FeedItem.fetched_time.asc())
            .limit(num_to_delete)
        )

        deleted_count = db.session.query(FeedItem).filter(FeedItem.id.in_(oldest_item_ids_q)).delete(synchronize_session=False)

        if deleted_count > 0:
            logger.info(f"Evicted {deleted_count} oldest items from feed '{feed_db_obj.name}' to enforce item limit.")
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error committing eviction of old items for feed '{feed_db_obj.name}': {e}", exc_info=True)

    return committed_items_count

def _apply_feed_update(feed, parsed_feed):
    """
    Applies updates to a feed from a parsed feed object.
    Helper used by both single and batch update operations.

    Args:
        feed: The Feed database object.
        parsed_feed: The result from feedparser.parse().

    Returns:
        tuple (success, new_items_count):
        - success (bool): True if processing completed (even with 0 items), False on critical failure.
        - new_items_count (int): Number of new items added.
    """
    if not parsed_feed:
        logger.error(f"Fetching content for feed '{feed.name}' (ID: {feed.id}) failed because fetch_feed returned None.")
        return False, 0

    if not parsed_feed.entries:
        logger.info(f"Feed '{feed.name}' (ID: {feed.id}) fetched successfully but contained no entries.")
        feed.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing feed update (no entries) for {feed.name}: {e}", exc_info=True)
        return True, 0

    try:
        new_items = process_feed_entries(feed, parsed_feed)
        return True, new_items
    except Exception as e:
        logger.error(f"An unexpected error occurred during entry processing for feed '{feed.name}' (ID: {feed.id}): {e}", exc_info=True)
        return False, 0

def fetch_and_update_feed(feed_id):
    """Fetches a single feed by ID, processes its entries, and updates the database.

    Args:
        feed_id (int): The database ID of the Feed to update.

    Returns:
        A tuple (success, new_items_count):
        - success (bool): True if the feed was fetched and processed successfully (even if 0 new items), False otherwise.
        - new_items_count (int): The number of new items added.
    """
    feed = db.session.get(Feed, feed_id)
    if not feed:
        logger.error(f"Feed with ID {feed_id} not found for update.")
        return False, 0

    parsed_feed = fetch_feed(feed.url)
    return _apply_feed_update(feed, parsed_feed)

def update_all_feeds():
    """Iterates through all feeds in the database, fetches updates in PARALLEL, and processes entries.

    Returns:
        A tuple (total_feeds_processed_successfully, total_new_items):
        - total_feeds_processed_successfully (int): Number of feeds where fetch and process stages completed without critical failure.
        - total_new_items (int): Total new items added across all feeds.
    """
    # Query for IDs and URLs only to avoid holding session-attached objects
    # that might get detached or stale during the long parallel fetch phase
    all_feeds_data = db.session.query(Feed.id, Feed.url).all()

    total_new_items = 0
    attempted_count = len(all_feeds_data)
    processed_successfully_count = 0

    logger.info(f"Starting parallel update process for {attempted_count} feeds with {FEED_FETCH_MAX_WORKERS} workers.")

    # Group feeds by URL to avoid redundant fetches
    feeds_by_url = defaultdict(list)
    for feed_id, url in all_feeds_data:
        feeds_by_url[url].append(feed_id)

    # Map future to URL for result handling
    with concurrent.futures.ThreadPoolExecutor(max_workers=FEED_FETCH_MAX_WORKERS) as executor:
        # Submit unique fetch tasks
        future_to_url = {
            executor.submit(fetch_feed, url): url
            for url in feeds_by_url.keys()
        }

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            feed_ids_for_url = feeds_by_url[url]
            try:
                # Add timeout to prevent indefinite blocking from a stuck worker/fetch
                # Even though fetch_feed has an internal timeout now, this is a safety net
                parsed_feed = future.result(timeout=FEED_FETCH_TIMEOUT + 5)

                # Apply the single fetch result to all feeds sharing this URL
                for feed_id in feed_ids_for_url:
                    # Get a fresh feed object from the DB session for each update.
                    # This ensures we are attached to the current session.
                    feed_obj = db.session.get(Feed, feed_id)
                    if not feed_obj:
                        logger.warning(f"Feed ID {feed_id} not found in database during update processing for URL {url}.")
                        continue

                    logger.info(f"Processing fetched data for feed: {feed_obj.name} ({feed_id})")
                    # We reuse the same parsed_feed object, which is efficient
                    success, new_items = _apply_feed_update(feed_obj, parsed_feed)

                    if success:
                        total_new_items += new_items
                        processed_successfully_count += 1

            except concurrent.futures.TimeoutError:
                logger.error(f"Timeout waiting for feed fetch to complete for URL {url} (affecting feed IDs: {feed_ids_for_url}).")
            except Exception as e:
                logger.exception(f"Error updating feeds for URL {url} (affecting feed IDs: {feed_ids_for_url}): {e}")
            
    logger.info(f"Finished updating feeds. Attempted: {attempted_count}, Successfully Processed: {processed_successfully_count}, Total New Items Added: {total_new_items}")
    return processed_successfully_count, total_new_items
