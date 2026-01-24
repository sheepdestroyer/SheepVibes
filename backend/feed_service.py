# Import necessary libraries
import feedparser
import datetime # Import the full module
from datetime import timezone # Specifically import timezone
import logging # Standard logging
import ssl # Added for specific SSL error catching
from dateutil import parser as date_parser # Use dateutil for robust date parsing
from sqlalchemy.exc import IntegrityError

# Import database models from the new models.py
from .models import db, Feed, FeedItem

# Set up logger for this module
logger = logging.getLogger(__name__)

# Maximum number of items to keep per feed for cache eviction
MAX_ITEMS_PER_FEED = 100

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

# --- Core Feed Processing Functions ---

def fetch_feed(feed_url):
    """Fetches and parses a feed using feedparser.

    Args:
        feed_url (str): The URL of the RSS/Atom feed.

    Returns:
        feedparser.FeedParserDict: A feedparser dictionary object, or None if
                                   fetching/parsing fails.
    """
    logger.info(f"Fetching feed: {feed_url}")
    try:
        parsed_feed = feedparser.parse(feed_url)

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
    batch_processed_guids = set()
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
        # The GUID is essential for uniquely identifying feed items over time.
        # While feedparser provides an 'id' field, it can be unreliable or non-unique in some feeds.
        # The item's link, however, is almost always unique.
        #
        # Previously, the logic tried to create a "true" GUID only if the feedparser 'id' was
        # different from the link, otherwise leaving it as None. This led to issues when
        # a feed used the same non-link 'id' for multiple, different items, causing a UNIQUE
        # constraint violation on (feed_id, guid).
        #
        # The new strategy is to always use the entry's link as the primary GUID. This ensures
        # that every item has a reliable, unique identifier, preventing database errors and
        # ensuring that updates are processed correctly.
        db_guid = entry_link

        # --- Deduplication Logic ---
        # 1. Check against items already in the DB *for this specific feed*
        if db_guid and db_guid in existing_feed_guids:
            # logger.debug(f"Item with db_guid '{db_guid}' already exists in DB for feed '{feed_db_obj.name}'. Skipping.")
            continue
        # Check link for this feed, critical for items that will have db_guid=None or if link is the primary identifier
        if entry_link in existing_feed_links:
            # logger.debug(f"Item with link '{entry_link}' already exists in DB for feed '{feed_db_obj.name}'. Skipping. (db_guid was: {db_guid})")
            continue

        # 2. Check against items already processed *in this current batch*
        is_batch_duplicate = False
        if db_guid: # If this item has a "true" GUID
            if db_guid in batch_processed_guids:
                logger.warning(f"Skipping item (true GUID: {db_guid}, link: {entry_link}) for feed '{feed_db_obj.name}', duplicate true GUID in current fetch batch.")
                is_batch_duplicate = True
        else: # No "true" GUID (db_guid is None), so batch uniqueness relies on the link
            if entry_link in batch_processed_links:
                logger.warning(f"Skipping item (link: {entry_link}) for feed '{feed_db_obj.name}', it has no true GUID and its link is a duplicate in current fetch batch.")
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

        published_time = parse_published_time(entry) # Already falls back to now()

        new_item = FeedItem(
            feed_id=feed_db_obj.id,
            title=entry_title,
            link=entry_link,
            published_time=published_time,
            guid=db_guid # This will be None if feedparser_id was missing or same as link
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

        # Ensure last_updated_time is set even if all individual inserts fail,
        # as the feed itself was successfully fetched and processed up to this point.
        # This needs to be part of a new transaction if the previous one was rolled back.
        try:
            feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
            db.session.add(feed_db_obj) # Re-add if it became detached after rollback
            db.session.commit()
        except Exception as ts_e:
            db.session.rollback()
            logger.error(f"Error updating last_updated_time for feed '{feed_db_obj.name}' after batch insert failure: {ts_e}", exc_info=True)

        for item_to_add in items_to_add:
            try:
                # Each item needs to be added to a fresh session or re-added if the session was rolled back.
                # If items were expunged by rollback, they might need to be re-created or merged.
                # Simplest is to re-add to current session if it's still active for individual commits.
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
    # After adding new items, check if the total number of items exceeds the limit.
    # If so, delete the oldest items to keep the total at the limit.
    current_item_count = db.session.query(FeedItem).filter_by(feed_id=feed_db_obj.id).count()

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
        deleted_count = db.session.query(FeedItem).filter(FeedItem.id.in_(oldest_item_ids_q)).delete(synchronize_session=False)

        if deleted_count > 0:
            logger.info(f"Evicted {deleted_count} oldest items from feed '{feed_db_obj.name}' to enforce item limit.")
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error committing eviction of old items for feed '{feed_db_obj.name}': {e}", exc_info=True)

    return committed_items_count

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
    if not parsed_feed:
        logger.error(f"Fetching content for feed '{feed.name}' (ID: {feed_id}) failed because fetch_feed returned None.")
        # Optionally update last_updated_time to now with a failure status
        # feed.last_updated_time = datetime.datetime.now(timezone.utc)
        # db.session.commit() # Be careful with commits in error paths
        return False, 0

    # Handle cases where feed is fetched but has no entries (common for new or empty feeds)
    if not parsed_feed.entries:
        logger.info(f"Feed '{feed.name}' (ID: {feed_id}) fetched successfully but contained no entries.")
        feed.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing feed update (no entries) for {feed.name}: {e}", exc_info=True)
            # Still, the fetch itself might be considered a "success" in terms of reachability
        return True, 0

    try:
        new_items = process_feed_entries(feed, parsed_feed)
        # process_feed_entries handles its own logging and commits for items and last_updated_time.
        # Success here means process_feed_entries completed without raising an exception to this level.
        return True, new_items
    except Exception as e: # Catch any unexpected error from process_feed_entries not caught internally
        logger.error(f"An unexpected error occurred during entry processing for feed '{feed.name}' (ID: {feed_id}): {e}", exc_info=True)
        return False, 0

def update_all_feeds():
    """Iterates through all feeds in the database, fetches updates, and processes entries.

    Returns:
        A tuple (total_feeds_processed_successfully, total_new_items):
        - total_feeds_processed_successfully (int): Number of feeds where fetch and process stages completed without critical failure.
        - total_new_items (int): Total new items added across all feeds.
    """
    all_feeds = Feed.query.all()
    total_new_items = 0
    attempted_count = 0
    processed_successfully_count = 0 # Feeds that completed fetch & process_feed_entries call
    
    logger.info(f"Starting update process for {len(all_feeds)} feeds.")

    for feed_obj in all_feeds: # Renamed to avoid conflict
        attempted_count += 1
        logger.info(f"Updating feed: {feed_obj.name} ({feed_obj.id}) - URL: {feed_obj.url}")
        try:
            success, new_items = fetch_and_update_feed(feed_obj.id)
            if success: # True if fetch_and_update_feed completed its course
                total_new_items += new_items
                processed_successfully_count +=1
            # Failures within fetch_and_update_feed are logged there.
        except Exception as e:
            # This catches unexpected errors during the loop for a specific feed,
            # e.g., if fetch_and_update_feed itself has an unhandled exception before returning.
            logger.error(f"Unexpected critical error in update_all_feeds loop for feed {feed_obj.name} ({feed_obj.id}): {e}", exc_info=True)
            # Continue to the next feed
            continue 
            
    logger.info(f"Finished updating feeds. Attempted: {attempted_count}, Successfully Processed (fetch & process stages): {processed_successfully_count}, Total New Items Added: {total_new_items}")
    return processed_successfully_count, total_new_items
