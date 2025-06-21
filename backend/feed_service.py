# Import necessary libraries
import feedparser
import datetime
from datetime import timezone # Import timezone
import time
import logging # Standard logging
import ssl # Added for specific SSL error catching
from dateutil import parser as date_parser # Use dateutil for robust date parsing
from sqlalchemy.exc import IntegrityError

# Import database models from the new models.py
from .models import db, Feed, FeedItem

# Set up logger for this module
logger = logging.getLogger(__name__)

# --- Helper Functions ---

def parse_published_time(entry):
    """Attempts to parse the published time from a feed entry.

    Args:
        entry: A feedparser entry object.

    Returns:
        A datetime object representing the published time (UTC aware),
        or None if parsing fails.
    """
    parsed_dt = None
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        # feedparser already parsed it
        try:
            # Convert feedparser's time struct to datetime
            # This is often naive but represents UTC as per feedparser docs for published_parsed
            parsed_dt = datetime.datetime(*entry.published_parsed[:6])
        except (TypeError, ValueError) as e:
            logger.debug(f"Failed to parse 'published_parsed' for entry {entry.get('link', '[no link]')}: {e}")
            parsed_dt = None # Ensure parsed_dt is None if parsing fails
    
    if parsed_dt is None:
        # Try common date fields using dateutil.parser for more flexibility
        date_fields = ['published', 'updated', 'created']
        for field in date_fields:
            if hasattr(entry, field):
                field_value = getattr(entry, field)
                if field_value: # Ensure there's a value to parse
                    try:
                        # Use dateutil.parser for robust parsing of various formats
                        parsed_dt = date_parser.parse(field_value)
                        if parsed_dt: # If parsing is successful, break from loop
                            break
                    except (ValueError, TypeError, OverflowError) as e: # Keep common exceptions for specific logging
                        logger.debug(f"Specific parsing error for date field '{field}' for entry {entry.get('link', '[no link]')} ({type(e).__name__}): {e}")
                        # Ignore parsing errors for this field and try the next
                        continue
                    except Exception as e: # Catch any other exceptions during parsing
                        logger.warning(f"Generic parsing error for date field '{field}' for entry {entry.get('link', '[no link]')} ({type(e).__name__}): {e}")
                        # Ignore parsing errors for this field and try the next
                        continue

    if parsed_dt:
        # Ensure the datetime is UTC timezone-aware
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
            # Datetime is naive, assume UTC and make it aware
            parsed_dt = parsed_dt.replace(tzinfo=datetime.timezone.utc)
        else:
            # Datetime is already timezone-aware, convert it to UTC
            parsed_dt = parsed_dt.astimezone(datetime.timezone.utc)
        return parsed_dt
                
    # If no date field is found or parsed successfully
    logger.warning(f"Could not parse published time for entry: {entry.get('link', '[no link]')}")
    return None

# --- Core Feed Processing Functions ---

def fetch_feed(feed_url):
    """Fetches and parses a feed using feedparser.

    Args:
        feed_url: The URL of the RSS/Atom feed.

    Returns:
        A feedparser dictionary object, or None if fetching/parsing fails.
    """
    logger.info(f"Fetching feed: {feed_url}")
    try:
        # Use feedparser to fetch and parse the feed
        # Consider adding etag and modified headers for conditional GET requests later
        parsed_feed = feedparser.parse(feed_url)
        
        # Check for basic parsing errors indicated by feedparser
        if parsed_feed.bozo:
            bozo_exc = parsed_feed.get('bozo_exception', Exception('Unknown parsing error (bozo=1)'))
            error_message = str(bozo_exc)

            # More specific logging for SSL/Certificate related bozo exceptions
            if "SSL" in error_message.upper() or \
               "CERTIFICATE" in error_message.upper() or \
               isinstance(bozo_exc, ssl.SSLError): # Check type as well
                logger.error(
                    f"Failed to fetch feed {feed_url} due to SSL/Certificate error (feedparser bozo): {error_message}",
                    exc_info=False # bozo_exception might not give a useful full traceback here
                )
            else:
                logger.warning(f"Feed is ill-formed: {feed_url} - Error: {error_message}")
            # Continue to return the (likely empty or incomplete) parsed_feed
            # as current logic does. If entries is empty, subsequent processing handles it.

        # Check if entries exist (even if not bozo, could be empty)
        if not parsed_feed.entries and not parsed_feed.bozo: # Avoid double logging if already warned by bozo
             logger.warning(f"No entries found in feed (and not a bozo feed): {feed_url}")
             # Return the parsed feed anyway, might contain metadata

        if not parsed_feed.bozo: # Log success only if not already handled by bozo warning/error
            logger.info(f"Successfully fetched feed: {feed_url}")
        return parsed_feed

    except ssl.SSLError as ssl_e: # Catch direct SSLError if it bypasses feedparser's bozo mechanism
        logger.error(f"Direct SSL Error during fetch attempt for {feed_url}: {ssl_e}", exc_info=True)
        return None
    except Exception as e:
        # Catch any other exceptions during fetching/parsing
        logger.error(f"Generic error fetching or parsing feed {feed_url}: {e}", exc_info=True)
        return None

def process_feed_entries(feed_db_obj, parsed_feed):
    """Processes entries from a parsed feed and adds new items to the database.

    Args:
        feed_db_obj: The Feed database object (SQLAlchemy model instance).
        parsed_feed: The dictionary object returned by feedparser.parse().

    Returns:
        The number of new items added to the database for this feed.
    """
    if not parsed_feed:
        logger.error(f"process_feed_entries called with a null parsed_feed for feed ID {feed_db_obj.id if feed_db_obj else 'Unknown'}")
        return 0

    new_items_count = 0
    processed_guids = set()
    processed_links = set()

    # Get existing GUIDs and links for this feed to avoid duplicates
    existing_items = db.session.query(FeedItem.guid, FeedItem.link).filter_by(feed_id=feed_db_obj.id).all()
    existing_guids = {item.guid for item in existing_items if item.guid}
    existing_links = {item.link for item in existing_items if item.link}

    # Update feed title if it has changed
    new_title = parsed_feed.feed.get('title')
    if new_title and new_title.strip() and new_title != feed_db_obj.name:
        logger.info(f"Updating feed title for '{feed_db_obj.name}' to '{new_title}'")
        feed_db_obj.name = new_title

    logger.info(f"Processing {len(parsed_feed.entries)} entries for feed: {feed_db_obj.name}")

    for entry in parsed_feed.entries:
        # Determine the unique identifier (GUID preferably, fallback to link)
        guid = entry.get('id')
        link = entry.get('link')
        title = entry.get('title', '[No Title]')

        # Validate Link (NOT NULL constraint in DB)
        if not link: # Handles None or empty string
            logger.warning(
                f"Skipping entry titled '{title[:100]}' for feed '{feed_db_obj.name}' "
                f"due to missing or empty link. (GUID for this entry was: {guid if guid else 'N/A'})"
            )
            continue

        # Basic validation: (already handled by link check if link is primary, but keep if guid can be sole identifier)
        # if not link and not guid: # This specific check might be redundant if link is now mandatory
        #     logger.warning(f"Skipping entry with no link or guid in feed {feed_db_obj.name}: '{title[:50]}...'")
        #     continue

        # Check for duplicates based on GUID or link against DB content and then batch content

        # Check against DB content
        if guid and guid in existing_guids:
            # logger.debug(f"Skipping item with existing GUID in DB: {guid} for feed {feed_db_obj.name}")
            continue
        # If GUID is new or missing, check link against DB.
        # An item with a new GUID should still be skipped if its link is a known duplicate in the DB.
        if link and link in existing_links:
            # logger.debug(f"Skipping item with existing Link in DB: {link} (GUID: {guid}) for feed {feed_db_obj.name}")
            continue

        # Check against current batch content (processed_guids and processed_links)
        # An item is a duplicate if its GUID is already processed in this batch OR its Link is already processed.
        if guid and guid in processed_guids:
            logger.warning(f"Skipping item (GUID: {guid}) for feed '{feed_db_obj.name}', duplicate GUID in current fetch batch.")
            continue
        if link and link in processed_links: # Check link even if GUID is new for this batch
            logger.warning(f"Skipping item (Link: {link}) for feed '{feed_db_obj.name}', duplicate Link in current fetch batch (GUID was: {guid}).")
            continue

        # If the item is not a duplicate by any of the above checks, then it's new.
        # Add its identifiers to the processed sets for this batch.
        if guid:
            processed_guids.add(guid)
        if link: # Add link to processed_links for all new items with links
            processed_links.add(link)

        # Parse published time
        published_time = parse_published_time(entry)

        # Create new FeedItem object
        new_item = FeedItem(
            feed_id=feed_db_obj.id,
            title=title,
            link=link,
            published_time=published_time,
            # fetched_time defaults to now
            is_read=False, # New items are always unread
            guid=guid
        )
        
        # Add to session
        db.session.add(new_item)
        new_items_count += 1
        # logger.debug(f"Adding new item: {title}")

    # Commit all new items for this feed at once
    try:
        # Update the feed's last updated time
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        db.session.commit()
        logger.info(f"Added {new_items_count} new items for feed: {feed_db_obj.name}")
    except IntegrityError as e:
        # Handle potential race conditions or unexpected unique constraint violations
        db.session.rollback()
        logger.error(f"Database integrity error processing feed {feed_db_obj.name}: {e}", exc_info=True)
        # Attempt to re-process individually or log/skip
        # For simplicity, we just log the error and return 0 for this run
        return 0 
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error committing new items for feed {feed_db_obj.name}: {e}", exc_info=True)
        return 0 # Indicate failure or partial success

    return new_items_count

def fetch_and_update_feed(feed_id):
    """Fetches a single feed by ID, processes its entries, and updates the database.

    Args:
        feed_id: The database ID of the Feed to update.

    Returns:
        A tuple (success, new_items_count):
        - success (bool): True if the feed was fetched and processed successfully, False otherwise.
        - new_items_count (int): The number of new items added.
    """
    feed = db.session.get(Feed, feed_id)
    if not feed:
        logger.error(f"Feed with ID {feed_id} not found for update.")
        return False, 0

    parsed_feed = fetch_feed(feed.url)
    if not parsed_feed:
        # Fetching failed (error already logged by fetch_feed)
        logger.error(f"Fetching content for feed {feed.name} (ID: {feed_id}) failed because fetch_feed returned None.")
        return False, 0

    # Process entries and update DB
    try:
        new_items = process_feed_entries(feed, parsed_feed)
        # process_feed_entries handles its own logging and commits
        
        # Consider success even if 0 new items, as long as fetch/process didn't error out
        return True, new_items
    except Exception as e:
        logger.error(f"An unexpected error occurred during entry processing for feed {feed.name} (ID: {feed_id}): {e}", exc_info=True)
        return False, 0

def update_all_feeds():
    """Iterates through all feeds in the database, fetches updates, and processes entries.
    
    Returns:
        A tuple (total_feeds_processed, total_new_items):
        - total_feeds_processed (int): Number of feeds attempted.
        - total_new_items (int): Total new items added across all feeds.
    """
    all_feeds = Feed.query.all()
    total_new_items = 0
    total_feeds_processed = 0
    
    logger.info(f"Starting update process for {len(all_feeds)} feeds.")

    for feed in all_feeds:
        logger.info(f"Updating feed: {feed.name} ({feed.id}) - URL: {feed.url}")
        try:
            # Use fetch_and_update_feed which encapsulates fetch and process logic
            success, new_items = fetch_and_update_feed(feed.id)
            if success:
                total_new_items += new_items
            # Log success/failure per feed if needed (already logged within functions)
            total_feeds_processed += 1
        except Exception as e:
            # Catch unexpected errors during the loop for a specific feed
            logger.error(f"Unexpected error updating feed {feed.name} ({feed.id}): {e}", exc_info=True)
            # Continue to the next feed
            continue 
            
    logger.info(f"Finished updating all feeds. Processed: {total_feeds_processed}, New Items: {total_new_items}")
    return total_feeds_processed, total_new_items
