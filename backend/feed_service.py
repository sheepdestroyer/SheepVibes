# Import necessary libraries
import feedparser
import datetime
import time
import logging
from dateutil import parser as date_parser # Use dateutil for robust date parsing
from sqlalchemy.exc import IntegrityError

# Import database models and session from the main app file
from app import db, Feed, FeedItem, logger # Assuming logger is configured in app.py

# --- Helper Functions ---

def parse_published_time(entry):
    """Attempts to parse the published time from a feed entry.

    Args:
        entry: A feedparser entry object.

    Returns:
        A datetime object representing the published time, or None if parsing fails.
    """
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        # feedparser already parsed it
        try:
            # Convert feedparser's time struct to datetime
            return datetime.datetime.fromtimestamp(time.mktime(entry.published_parsed))
        except (TypeError, ValueError):
            pass # Fall through to dateutil parsing
    
    # Try common date fields using dateutil.parser for more flexibility
    date_fields = ['published', 'updated', 'created']
    for field in date_fields:
        if hasattr(entry, field):
            try:
                # Use dateutil.parser for robust parsing of various formats
                return date_parser.parse(getattr(entry, field))
            except (ValueError, TypeError, OverflowError):
                # Ignore parsing errors for this field and try the next
                continue
                
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
            bozo_exception = parsed_feed.get('bozo_exception', 'Unknown parsing error')
            logger.warning(f"Feed is ill-formed: {feed_url} - Error: {bozo_exception}")
            # Decide if you want to proceed despite bozo=1 (might still have usable data)
            # For now, we'll proceed but log the warning.

        # Check if entries exist
        if not parsed_feed.entries:
             logger.warning(f"No entries found in feed: {feed_url}")
             # Return the parsed feed anyway, might contain metadata

        logger.info(f"Successfully fetched feed: {feed_url}")
        return parsed_feed
        
    except Exception as e:
        # Catch any other exceptions during fetching/parsing
        logger.error(f"Error fetching or parsing feed {feed_url}: {e}", exc_info=True)
        return None

def process_feed_entries(feed_db_obj, parsed_feed):
    """Processes entries from a parsed feed and adds new items to the database.

    Args:
        feed_db_obj: The Feed database object (SQLAlchemy model instance).
        parsed_feed: The dictionary object returned by feedparser.parse().

    Returns:
        The number of new items added to the database for this feed.
    """
    if not parsed_feed or not parsed_feed.entries:
        logger.info(f"No entries to process for feed: {feed_db_obj.name} ({feed_db_obj.id})")
        return 0

    new_items_count = 0
    processed_guids = set()
    processed_links = set()

    # Get existing GUIDs and links for this feed to avoid duplicates
    existing_items = db.session.query(FeedItem.guid, FeedItem.link).filter_by(feed_id=feed_db_obj.id).all()
    existing_guids = {item.guid for item in existing_items if item.guid}
    existing_links = {item.link for item in existing_items if item.link}

    logger.info(f"Processing {len(parsed_feed.entries)} entries for feed: {feed_db_obj.name}")

    for entry in parsed_feed.entries:
        # Determine the unique identifier (GUID preferably, fallback to link)
        guid = entry.get('id')
        link = entry.get('link')
        title = entry.get('title', '[No Title]')

        # Basic validation: Ensure we have at least a link or guid
        if not link and not guid:
            logger.warning(f"Skipping entry with no link or guid in feed {feed_db_obj.name}: '{title[:50]}...'")
            continue

        # Check for duplicates based on GUID or link within this batch and existing DB items
        is_duplicate = False
        if guid:
            if guid in existing_guids or guid in processed_guids:
                is_duplicate = True
            else:
                processed_guids.add(guid)
        elif link: # Only check link if GUID is missing
            if link in existing_links or link in processed_links:
                is_duplicate = True
            else:
                processed_links.add(link)

        if is_duplicate:
            # logger.debug(f"Skipping duplicate item (GUID: {guid}, Link: {link}) for feed {feed_db_obj.name}")
            continue

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
        feed_db_obj.last_updated_time = datetime.datetime.utcnow()
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
    feed = Feed.query.get(feed_id)
    if not feed:
        logger.error(f"Feed with ID {feed_id} not found for update.")
        return False, 0

    parsed_feed = fetch_feed(feed.url)
    if not parsed_feed:
        # Fetching failed (error already logged by fetch_feed)
        return False, 0

    # Process entries and update DB
    new_items = process_feed_entries(feed, parsed_feed)
    # process_feed_entries handles its own logging and commits
    
    # Consider success even if 0 new items, as long as fetch/process didn't error out
    return True, new_items 

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
