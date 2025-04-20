import feedparser
import logging
import datetime
from sqlalchemy.exc import SQLAlchemyError
from app import db, Feed, FeedItem, logger

def fetch_feed(feed_url):
    """
    Fetch and parse an RSS/Atom feed from the given URL.
    
    Args:
        feed_url (str): The URL of the feed to fetch
        
    Returns:
        dict: Parsed feed or None if an error occurred
    """
    try:
        logger.info(f"Fetching feed from {feed_url}")
        feed = feedparser.parse(feed_url)
        
        if feed.get('bozo_exception'):
            logger.warning(f"Feed parsing error for {feed_url}: {feed.bozo_exception}")
            if not feed.get('entries'):
                logger.warning(f"No entries found for feed {feed_url} with parsing error: {feed.bozo_exception}")
                return None
        return feed
    except Exception as e:
        logger.error(f"Error fetching feed from {feed_url}: {str(e)}")
        return None

def update_feed_data(feed_obj, parsed_feed):
    """
    Update feed metadata from parsed feed data.
    
    Args:
        feed_obj (Feed): Feed database object to update
        parsed_feed (dict): Parsed feed from feedparser
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Update feed name if it's available in the parsed feed
        if parsed_feed.get('feed') and parsed_feed['feed'].get('title'):
            feed_obj.name = parsed_feed['feed']['title']
        
        feed_obj.last_updated_time = datetime.datetime.utcnow()
        db.session.commit()
        return True
    except SQLAlchemyError as e:
        logger.error(f"Database error updating feed data: {str(e)}")
        db.session.rollback()
        return False
    except Exception as e:
        logger.error(f"Error updating feed data: {str(e)}")
        db.session.rollback()
        return False

def process_feed_entries(feed_obj, parsed_feed):
    """
    Process entries from a parsed feed and add new items to the database.
    
    Args:
        feed_obj (Feed): Feed database object to associate items with
        parsed_feed (dict): Parsed feed from feedparser
        
    Returns:
        int: Number of new items added
    """
    if not parsed_feed or not parsed_feed.get('entries'):
        return 0
    
    new_items_count = 0
    
    try:
        for entry in parsed_feed.entries:
            # Skip entries without title or link
            if not entry.get('title') or not entry.get('link'):
                continue
            
            # Extract GUID or use link as fallback
            guid = entry.get('id', entry.get('guid', entry.link))
            
            # Check if item already exists to avoid duplicates
            existing_item = FeedItem.query.filter_by(guid=guid).first()
            if existing_item:
                continue
            
            # Parse published time if available
            published_time = None
            if entry.get('published_parsed'):
                try:
                try:
                    published_time = datetime.datetime.fromisoformat(entry.published)
                except (TypeError, ValueError) as e:
                    logger.warning(f"Error parsing published date: {str(e)}")
            
            # Create new feed item
            feed_item = FeedItem(
                feed_id=feed_obj.id,
                title=entry.title,
                link=entry.link,
                published_time=published_time,
                fetched_time=datetime.datetime.utcnow(),
                is_read=False,
                guid=guid
            )
            
            db.session.add(feed_item)
            new_items_count += 1
        
        # Commit all new items in a single transaction
        if new_items_count > 0:
            try:
                db.session.commit()
                logger.info(f"Added {new_items_count} new items for feed '{feed_obj.name}'")
            except SQLAlchemyError as e:
                logger.error(f"Database error committing feed items: {str(e)}")
                db.session.rollback()
            
        return new_items_count
            
    except SQLAlchemyError as e:
        logger.error(f"Database error processing feed entries: {str(e)}")
        db.session.rollback()
        return 0
    except Exception as e:
        logger.error(f"Error processing feed entries: {str(e)}")
        db.session.rollback()
        return 0

def fetch_and_update_feed(feed_id):
    """
    Fetch, process and update a single feed by ID.
    
    Args:
        feed_id (int): ID of the feed to update
        
    Returns:
        tuple: (success: bool, new_items: int)
    """
    try:
        feed = Feed.query.get(feed_id)
        if not feed:
            logger.warning(f"Feed with ID {feed_id} not found")
            return False, 0
        
        parsed_feed = fetch_feed(feed.url)
        if not parsed_feed:
            logger.warning(f"Failed to fetch feed from {feed.url}")
            return False, 0
        
        updated = update_feed_data(feed, parsed_feed)
        new_items = process_feed_entries(feed, parsed_feed)
        
        return updated, new_items
    except Exception as e:
        logger.error(f"Error in fetch_and_update_feed for feed ID {feed_id}: {str(e)}")
        return False, 0

def update_all_feeds():
    """
    Update all feeds in the database.
    
    Returns:
        tuple: (feeds_updated: int, total_new_items: int)
    """
    feeds_updated = 0
    total_new_items = 0
    
    try:
        feeds = Feed.query.all()
        logger.info(f"Starting update for {len(feeds)} feeds")
        
        for feed in feeds:
            success, new_items = fetch_and_update_feed(feed.id)
            if success:
                feeds_updated += 1
                total_new_items += new_items
        
        logger.info(f"Feed update completed: {feeds_updated} feeds updated, {total_new_items} new items")
        return feeds_updated, total_new_items
    except Exception as e:
        logger.error(f"Error updating feeds: {str(e)}")
        return feeds_updated, total_new_items
