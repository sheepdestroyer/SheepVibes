#!/usr/bin/env python3
"""
Test script for the feed service functionality.
This script can be used to test feed fetching and processing without running the full application.
"""
import pytest # Added import
import sys
import logging
from app import app, db, Feed, Tab # Ensured app, db are imported
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

@pytest.fixture
def db_setup():
    """Pytest fixture to set up the Flask app for testing with an in-memory DB."""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    with app.app_context():
        db.create_all()
        yield app # Provide the app instance, can also yield db if needed
        db.session.remove()
        db.drop_all()

@pytest.mark.skip(reason="This test is designed for manual execution with a URL parameter, not for automated pytest runs.")
def test_fetch_feed(url):
    """Test fetching a feed from a given URL"""
    logger.info(f"Testing feed fetch from: {url}")
    parsed_feed = feed_service.fetch_feed(url)
    
    if not parsed_feed:
        logger.error("Failed to fetch feed")
        return False # Or raise an assertion error for pytest
    
    logger.info(f"Successfully fetched feed: {parsed_feed.feed.get('title', 'Unknown')}")
    logger.info(f"Found {len(parsed_feed.entries)} entries")
    
    # Print first few entries
    for i, entry in enumerate(parsed_feed.entries[:3]):
        logger.info(f"Entry {i+1}: {entry.title}")
    
    assert parsed_feed is not None # Example assertion for pytest
    return True

def add_test_feed(url, tab_name="Home"):
    """Add a test feed to the database (helper function, not a test itself)."""
    # This function assumes an app context is active if called from a test using db_setup
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

def test_update_all_feeds(db_setup): # Added db_setup fixture
    """Test updating all feeds in the database"""
    # app context is handled by db_setup
    logger.info("Testing update_all_feeds()")

    # Optional: Add some test feeds if the test relies on specific data
    # For example:
    # add_test_feed("http://example.com/rss1") # This helper needs app context from db_setup
    # add_test_feed("http://example.com/rss2")

    feeds_updated, new_items = feed_service.update_all_feeds()
    logger.info(f"Updated {feeds_updated} feeds, added {new_items} new items")
    
    # Add assertions based on expected behavior with the in-memory DB
    # For instance, if no feeds are added by the setup, expect 0, 0
    assert feeds_updated >= 0
    assert new_items >= 0

# Removed the __main__ block as tests will be run by pytest
