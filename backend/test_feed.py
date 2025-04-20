#!/usr/bin/env python3
"""
Test script for the feed service functionality.
This script can be used to test feed fetching and processing without running the full application.
"""

import sys
import logging
from app import app, db, Feed, Tab
import feed_service

# Set up logging to console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sheepvibes_test')

def test_fetch_feed(url):
    """Test fetching a feed from a given URL"""
    logger.info(f"Testing feed fetch from: {url}")
    parsed_feed = feed_service.fetch_feed(url)
    
    if not parsed_feed:
        logger.error("Failed to fetch feed")
        return False
    
    logger.info(f"Successfully fetched feed: {parsed_feed.feed.get('title', 'Unknown')}")
    logger.info(f"Found {len(parsed_feed.entries)} entries")
    
    # Print first few entries
    for i, entry in enumerate(parsed_feed.entries[:3]):
        logger.info(f"Entry {i+1}: {entry.title}")
    
    return True

def add_test_feed(url, tab_name="Home"):
    """Add a test feed to the database"""
    with app.app_context():
        # Find or create tab
        tab = Tab.query.filter_by(name=tab_name).first()
        if not tab:
            logger.info(f"Creating new tab: {tab_name}")
            tab = Tab(name=tab_name, order=0)
            db.session.add(tab)
            db.session.commit()
        
        # Fetch feed to get title
        parsed_feed = feed_service.fetch_feed(url)
        if not parsed_feed:
            logger.error(f"Failed to fetch feed from {url}")
            return None
            
        feed_title = parsed_feed.feed.get('title', 'Unknown Feed')
        
        # Check if feed already exists
        existing_feed = Feed.query.filter_by(url=url).first()
        if existing_feed:
            logger.info(f"Feed already exists: {feed_title}")
            return existing_feed
            
        # Create new feed
        logger.info(f"Adding new feed: {feed_title}")
        feed = Feed(
            tab_id=tab.id,
            name=feed_title,
            url=url
        )
        db.session.add(feed)
        db.session.commit()
        
        # Process feed entries
        new_items = feed_service.process_feed_entries(feed, parsed_feed)
        logger.info(f"Added {new_items} new items for feed '{feed.name}'")
        
        return feed

def test_update_all_feeds():
    """Test updating all feeds in the database"""
    with app.app_context():
        logger.info("Testing update_all_feeds()")
        feeds_updated, new_items = feed_service.update_all_feeds()
        logger.info(f"Updated {feeds_updated} feeds, added {new_items} new items")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # If URL provided, test that specific feed
        url = sys.argv[1]
        test_fetch_feed(url)
        add_test_feed(url)
    else:
        # Otherwise run some default tests
        default_feeds = [
            "https://news.ycombinator.com/rss",
            "https://feeds.feedburner.com/TechCrunch",
            "https://www.reddit.com/r/programming/.rss"
        ]
        
        logger.info("No URL provided. Testing with default feeds.")
        for url in default_feeds:
            if test_fetch_feed(url):
                add_test_feed(url)
        
        test_update_all_feeds()
    
    logger.info("Tests completed.")
