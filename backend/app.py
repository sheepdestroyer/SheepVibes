# Import necessary libraries
import os
import logging
import atexit
import queue
import json
from flask import Flask, jsonify, request, send_from_directory, Response
# Removed SQLAlchemy direct import, will get `db` from models
from flask_migrate import Migrate # Added for database migrations
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
from sqlalchemy import func, select # Added for optimized query
from sqlalchemy.orm import selectinload # Added for eager loading
from flask_caching import Cache # Added for caching
from flask_cors import CORS # Added for CORS support

# Import db object and models from the new models.py
from .models import db, Tab, Feed, FeedItem
import xml.etree.ElementTree as ET # Added for OPML export

# --- OPML Import Configuration ---
SKIPPED_FOLDER_TYPES = {"UWA", "Webnote", "LinkModule"} # Netvibes specific types to ignore for tab creation

# --- Application Constants ---
DEFAULT_FEED_ITEMS_LIMIT = 10

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler() # Log to standard output
    ]
)
logger = logging.getLogger('sheepvibes')

class MessageAnnouncer:
    """A simple message announcer that uses server-sent events.

    This class manages a list of listener queues. When a message is announced,
    it is put into each queue. The listen method yields messages from a queue,
    allowing for real-time communication with clients.
    """

    def __init__(self):
        """Initializes the MessageAnnouncer."""
        self.listeners = []

    def listen(self):
        """Listens for messages and yields them to the client.

        This is a generator function that maintains a connection with the client.
        It adds a new queue to the listeners and then enters an infinite loop,
        yielding messages as they become available.

        Yields:
            str: A message from the queue, formatted for SSE.
        """
        q = queue.Queue(maxsize=5)
        self.listeners.append(q)
        try:
            while True:
                try:
                    # Using a timeout on get() makes the loop non-blocking from the
                    # perspective of the wsgi server, allowing it to handle client
                    # disconnects gracefully.
                    msg = q.get(timeout=1.0)
                    yield msg
                except queue.Empty:
                    # Send a heartbeat comment to keep the connection alive
                    # and, crucially, to provide a yield point for GeneratorExit
                    # to be raised when the client disconnects.
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            # This is triggered when the client disconnects
            self.listeners.remove(q)

    def announce(self, msg):
        """Announces a message to all listening clients.

        Args:
            msg (str): The message to announce.
        """
        # Use a copy of the list to avoid issues if a client disconnects
        # during iteration.
        for q in list(self.listeners):
            try:
                q.put_nowait(msg)
            except queue.Full:
                # Client's queue is full, drop the message.
                logger.warning("A client's SSE message queue was full. Dropping message.")
                pass

announcer = MessageAnnouncer()

# Initialize Flask application
app = Flask(__name__)
# Configure CORS with specific allowed origins
allowed_origins_str = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()]
CORS(app, origins=allowed_origins, resources={r"/api/*": {}})

# Constants
MAX_PAGINATION_LIMIT = 100
DEFAULT_PAGINATION_LIMIT = 10

# Test specific configuration
# Check app.config first in case it's set by test runner, then env var
if app.config.get('TESTING') or os.environ.get('TESTING') == 'true':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True # Ensure it's explicitly True in app.config
    app.config['CACHE_TYPE'] = 'SimpleCache' # Use SimpleCache for tests, no Redis needed
    logger.info("TESTING mode: Using in-memory SQLite database and SimpleCache.")
else:
    # Existing database configuration logic
    default_db_path_in_container = '/app/data/sheepvibes.db'
    db_path_env = os.environ.get('DATABASE_PATH')

    if db_path_env:
        if db_path_env.startswith('sqlite:///'):
            app.config['SQLALCHEMY_DATABASE_URI'] = db_path_env
            logger.info(f"Using DATABASE_PATH environment variable directly: {db_path_env}")
        else:
            db_path = db_path_env
            app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
            logger.info(f"Using DATABASE_PATH environment variable for file path: {db_path}")
    else:
        # Default path logic
        if not os.path.exists('/app'): # Assume local development
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            local_data_dir = os.path.join(project_root, 'data')
            os.makedirs(local_data_dir, exist_ok=True)
            db_path = os.path.join(local_data_dir, 'sheepvibes.db')
            logger.info(f"DATABASE_PATH not set, assuming local run. Using file path: {db_path}")
        else: # Assume container run
            db_path = default_db_path_in_container
            logger.info(f"DATABASE_PATH not set, assuming container run. Using default file path: {db_path}")
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

    # --- Cache Configuration for non-testing ---
    app.config["CACHE_TYPE"] = "RedisCache"
    app.config["CACHE_REDIS_URL"] = os.environ.get("CACHE_REDIS_URL", "redis://localhost:6379/0")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable modification tracking
# CACHE_DEFAULT_TIMEOUT is now set within the TESTING if/else block or defaults if not.
# Ensure CACHE_TYPE and relevant URLs are fully set before Cache() is instantiated or init_app'd.

cache = Cache() # Create the cache instance

# Initialize SQLAlchemy ORM extension with the app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize the cache with the app config
cache.init_app(app)

# --- Cache Key Generation and Invalidation ---

def get_version(key, default=1):
    """Gets a version number for a cache key from the cache.

    Args:
        key (str): The cache key for the version number.
        default (int): The default version number to return if the key is not found.

    Returns:
        int: The version number.
    """
    return cache.get(key) or default

def make_tabs_cache_key(*args, **kwargs):
    """Creates a cache key for the main tabs list, incorporating a version.

    Args:
        *args: Additional arguments (unused).
        **kwargs: Additional keyword arguments (unused).

    Returns:
        str: The generated cache key.
    """
    version = get_version('tabs_version')
    return f'view/tabs/v{version}'

def make_tab_feeds_cache_key(tab_id):
    """Creates a cache key for a specific tab's feeds, incorporating version and query params.

    Args:
        tab_id (int): The ID of the tab.

    Returns:
        str: The generated cache key.
    """
    tabs_version = get_version('tabs_version') # For unread counts
    tab_version = get_version(f'tab_{tab_id}_version')
    query_string = request.query_string.decode().replace('&', '_') # Sanitize for key
    return f'view/tab/{tab_id}/v{tab_version}/tabs_v{tabs_version}/?{query_string}'

def invalidate_tabs_cache():
    """Invalidates the tabs list cache by incrementing its version."""
    version_key = 'tabs_version'
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info(f"Invalidated tabs cache. New version: {new_version}")

def invalidate_tab_feeds_cache(tab_id):
    """Invalidates a specific tab's feed cache and the main tabs list cache.

    Args:
        tab_id (int): The ID of the tab to invalidate the cache for.
    """
    version_key = f'tab_{tab_id}_version'
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info(f"Invalidated cache for tab {tab_id}. New version: {new_version}")
    # Also invalidate the main tabs list because unread counts will have changed.
    invalidate_tabs_cache()

# --- Feed Update Service and Scheduler ---

# Import feed service functions
from .feed_service import update_all_feeds, fetch_and_update_feed, fetch_feed, process_feed_entries

# Configure the background scheduler
UPDATE_INTERVAL_MINUTES_DEFAULT = 15
# Get update interval from environment variable or use default
UPDATE_INTERVAL_MINUTES = int(os.environ.get('UPDATE_INTERVAL_MINUTES', UPDATE_INTERVAL_MINUTES_DEFAULT))
scheduler = BackgroundScheduler()

# Define the scheduled job function
@scheduler.scheduled_job('interval', minutes=UPDATE_INTERVAL_MINUTES, id='update_feeds')
def scheduled_feed_update():
    """Scheduled job to periodically update all feeds in the database."""
    # Need app context to access database within the scheduled job
    with app.app_context():
        logger.info(f"Running scheduled feed update (every {UPDATE_INTERVAL_MINUTES} minutes)")
        try:
            feeds_updated, new_items = update_all_feeds()
            logger.info(f"Scheduled update completed: {feeds_updated} feeds updated, {new_items} new items")
            # Invalidate the cache after updates
            if new_items > 0:
                cache.clear()
                logger.info("Cache cleared after scheduled update found new items.")
            
            # Announce the update to any listening clients
            event_data = {'feeds_processed': feeds_updated, 'new_items': new_items}
            msg = f"data: {json.dumps(event_data)}\n\n"
            announcer.announce(msg=msg)
        except Exception as e:
            logger.error(f"Error during scheduled feed update: {e}", exc_info=True)

# Start the scheduler in the global scope for WSGI servers and register a cleanup function.
try:
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()

# --- Error Handlers ---

@app.errorhandler(404)
def not_found_error(error):
    """Handles 404 Not Found errors with a JSON response.

    Args:
        error: The error object.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    logger.warning(f"404 Not Found: {request.path}")
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handles 500 Internal Server Errors with a JSON response and logs the error.

    Args:
        error: The error object.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    logger.error(f"500 Internal Server Error: {error}", exc_info=True)
    # Rollback the session in case the error was database-related
    db.session.rollback()
    return jsonify({'error': 'An internal server error occurred'}), 500

# --- API Routes ---

# Serve Frontend Files
FRONTEND_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

@app.route('/')
def serve_index():
    """Serves the main index.html file."""
    return send_from_directory(FRONTEND_FOLDER, 'index.html')

@app.route('/<path:filename>')
def serve_static_files(filename):
    """Serves static files like CSS and JS from the frontend folder.

    Args:
        filename (str): The name of the file to serve.

    Returns:
        A Flask Response object containing the file, or a JSON error response.
    """
    # Basic security check: prevent accessing files outside the frontend folder
    if ".." in filename or filename.startswith("/"):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory(FRONTEND_FOLDER, filename)

# --- SSE Stream Endpoint ---
@app.route('/api/stream')
def stream():
    """Endpoint for Server-Sent Events (SSE) to stream updates."""
    return Response(announcer.listen(), mimetype='text/event-stream')

# --- OPML Export Endpoint ---

@app.route('/api/opml/export', methods=['GET'])
def export_opml():
    """Exports all feeds as an OPML file.

    Returns:
        A Flask Response object containing the OPML file, or a JSON error response.
    """
    try:
        opml_element = ET.Element('opml', version='2.0')
        head_element = ET.SubElement(opml_element, 'head')
        title_element = ET.SubElement(head_element, 'title')
        title_element.text = 'SheepVibes Feeds'
        body_element = ET.SubElement(opml_element, 'body')

        # Eager load feeds to avoid N+1 queries
        tabs = Tab.query.options(selectinload(Tab.feeds)).order_by(Tab.order).all()

        for tab in tabs:
            # Skip tabs with no feeds
            if not tab.feeds:
                continue

            # Create a folder outline for the tab
            folder_outline = ET.SubElement(body_element, 'outline')
            folder_outline.set('text', tab.name)
            folder_outline.set('title', tab.name)

            # Sort feeds by name for deterministic output because relation order is not guaranteed
            sorted_feeds = sorted(tab.feeds, key=lambda f: f.name)

            # Add feeds for this tab
            for feed in sorted_feeds:
                feed_outline = ET.SubElement(folder_outline, 'outline')
                feed_outline.set('text', feed.name)
                feed_outline.set('title', feed.name)
                feed_outline.set('xmlUrl', feed.url)
                feed_outline.set('type', 'rss')
                if feed.site_link:
                    feed_outline.set('htmlUrl', feed.site_link)

        # Convert the XML tree to a string
        opml_string = ET.tostring(opml_element, encoding='utf-8', method='xml').decode('utf-8')

        response = Response(opml_string, mimetype='application/xml')
        response.headers['Content-Disposition'] = 'attachment; filename="sheepvibes_feeds.opml"'

        feed_count = sum(len(tab.feeds) for tab in tabs)
        logger.info(f"Successfully generated OPML export for {feed_count} feeds across {len(tabs)} tabs.")
        return response

    except Exception as e:
        logger.error(f"Error during OPML export: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to generate OPML export'}), 500

# --- OPML Import Endpoint ---

def _process_opml_outlines_recursive(
    outline_elements,
    current_tab_id,
    current_tab_name, # For logging/context, not strictly for db ops here
    all_existing_feed_urls_set,
    newly_added_feeds_list,
    imported_count_wrapper, # Use list/dict for mutable integer
    skipped_count_wrapper,  # Use list/dict for mutable integer
    affected_tab_ids_set
):
    """Recursively processes OPML outline elements.

    Feeds are added to `newly_added_feeds_list` but not committed here.
    New tabs (folders) are committed immediately to get their IDs.

    Args:
        outline_elements (list): A list of XML elements to process.
        current_tab_id (int): The ID of the current tab to add feeds to.
        current_tab_name (str): The name of the current tab.
        all_existing_feed_urls_set (set): A set of all existing feed URLs to prevent duplicates.
        newly_added_feeds_list (list): A list to append new Feed objects to.
        imported_count_wrapper (list): A list containing a single integer to track the imported count.
        skipped_count_wrapper (list): A list containing a single integer to track the skipped count.
        affected_tab_ids_set (set): A set to track the IDs of tabs that have new feeds added.
    """
    for outline_element in outline_elements:
        folder_type_attr = outline_element.get('type') # For Netvibes type skipping
        # Netvibes uses 'title', some others use 'text'. Prioritize 'title'.
        title_attr = outline_element.get('title')
        text_attr = outline_element.get('text')
        element_name = title_attr.strip() if title_attr and title_attr.strip() else \
                       (text_attr.strip() if text_attr and text_attr.strip() else "")

        xml_url = outline_element.get('xmlUrl')
        child_outlines = list(outline_element) # More robust than findall for direct children

        if xml_url: # It's a feed
            feed_name = element_name if element_name else xml_url # Fallback to URL if no title/text

            if xml_url in all_existing_feed_urls_set:
                logger.info(f"OPML import: Feed with URL '{xml_url}' already exists. Skipping.")
                skipped_count_wrapper[0] += 1
                continue

            try:
                new_feed = Feed(
                    tab_id=current_tab_id,
                    name=feed_name,
                    url=xml_url
                )
                # Add to session, but commit will be done in batch later for feeds
                db.session.add(new_feed)
                newly_added_feeds_list.append(new_feed)
                all_existing_feed_urls_set.add(xml_url) # Track for current import session
                imported_count_wrapper[0] += 1
                affected_tab_ids_set.add(current_tab_id)
                logger.info(f"OPML import: Prepared new feed '{feed_name}' ({xml_url}) for tab ID {current_tab_id} ('{current_tab_name}').")
            except Exception as e_feed:
                # Should be rare if checks are done, but good for safety
                logger.error(f"OPML import: Error preparing feed '{feed_name}': {e_feed}", exc_info=True)
                skipped_count_wrapper[0] += 1

        elif not xml_url and element_name and folder_type_attr and folder_type_attr in SKIPPED_FOLDER_TYPES:
            logger.info(f"OPML import: Skipping Netvibes-specific folder '{element_name}' due to type: {folder_type_attr}.")
            # Children of these folders are also skipped.
            # If we needed to count skipped items within, we'd need to parse child_outlines here.
            # For now, the folder itself is skipped from becoming a tab, and its contents aren't processed.
            continue # Effectively skips this folder and its children for tab/feed creation

        elif not xml_url and element_name and child_outlines: # It's a folder (has a name, no xmlUrl, AND children)
            folder_name = element_name
            existing_tab = Tab.query.filter_by(name=folder_name).first()

            nested_tab_id = None
            nested_tab_name = None

            if existing_tab:
                nested_tab_id = existing_tab.id
                nested_tab_name = existing_tab.name
                logger.info(f"OPML import: Folder '{folder_name}' matches existing tab '{nested_tab_name}' (ID: {nested_tab_id}). Feeds will be added to it.")
            else:
                max_order = db.session.query(db.func.max(Tab.order)).scalar()
                new_order = (max_order or -1) + 1
                new_folder_tab = Tab(name=folder_name, order=new_order)
                db.session.add(new_folder_tab)
                try:
                    db.session.commit() # Commit new tab immediately to get its ID
                    logger.info(f"OPML import: Created new tab '{new_folder_tab.name}' (ID: {new_folder_tab.id}) from OPML folder.")
                    invalidate_tabs_cache() # Crucial: new tab added
                    nested_tab_id = new_folder_tab.id
                    nested_tab_name = new_folder_tab.name
                except Exception as e_tab_commit:
                    db.session.rollback()
                    logger.error(f"OPML import: Failed to commit new tab '{folder_name}': {e_tab_commit}. Skipping this folder and its contents.", exc_info=True)
                    skipped_count_wrapper[0] += len(child_outlines) # Approximate skip count
                    continue # Skip this folder

            if nested_tab_id and nested_tab_name: # child_outlines is already checked by the elif condition
                _process_opml_outlines_recursive(
                    child_outlines,
                    nested_tab_id,
                    nested_tab_name,
                    all_existing_feed_urls_set,
                    newly_added_feeds_list,
                    imported_count_wrapper,
                    skipped_count_wrapper,
                    affected_tab_ids_set
                )
        elif not xml_url and not element_name and child_outlines:
            # Folder without a title, process its children in the current tab
            logger.info(f"OPML import: Processing children of an untitled folder under current tab '{current_tab_name}'.")
            _process_opml_outlines_recursive(
                child_outlines,
                current_tab_id, # Use current tab_id
                current_tab_name,
                all_existing_feed_urls_set,
                newly_added_feeds_list,
                imported_count_wrapper,
                skipped_count_wrapper,
                affected_tab_ids_set
            )
        else:
            # An outline element that is neither a feed, a folder with children, nor an untitled folder with children.
            # This includes empty folders (name, no xmlUrl, no children) which will now be skipped.
            logger.info(f"OPML import: Skipping outline element (Name: '{element_name}', xmlUrl: {xml_url}, Children: {len(child_outlines)}) as it's not a feed or a non-empty folder.")
            if not xml_url: # If it's not a feed (it might be an empty folder or an invalid item)
                 skipped_count_wrapper[0] +=1


@app.route('/api/opml/import', methods=['POST'])
def import_opml():
    """Imports feeds from an OPML file, supporting nested structures as new tabs."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    opml_file = request.files['file']
    if opml_file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400
    if not opml_file:
        return jsonify({'error': 'File object is empty'}), 400

    # Using lists for mutable integers to pass by reference into recursion
    imported_count_wrapper = [0]
    skipped_count_wrapper = [0]
    affected_tab_ids_set = set()
    newly_added_feeds_list = []

    try:
        tree = ET.parse(opml_file.stream)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"OPML import failed: Malformed XML. Error: {e}", exc_info=True)
        return jsonify({'error': f'Malformed OPML file: {e}'}), 400
    except Exception as e:
        logger.error(f"OPML import failed: Could not parse file stream. Error: {e}", exc_info=True)
        return jsonify({'error': f'Error processing OPML file: {e}'}), 500

    # --- Determine initial/top-level target tab ---
    top_level_target_tab_id = None
    top_level_target_tab_name = None
    requested_tab_id_str = request.form.get('tab_id')

    if requested_tab_id_str:
        try:
            tab_id_val = int(requested_tab_id_str)
            tab_obj = db.session.get(Tab, tab_id_val)
            if tab_obj:
                top_level_target_tab_id = tab_obj.id
                top_level_target_tab_name = tab_obj.name
            else:
                logger.warning(f"OPML import: Requested tab_id {tab_id_val} not found. Will use default logic.")
        except ValueError:
            logger.warning(f"OPML import: Invalid tab_id format '{requested_tab_id_str}'. Will use default logic.")

    if not top_level_target_tab_id: # If no valid tab_id from request, or no request
        default_tab_obj = Tab.query.order_by(Tab.order).first()
        if default_tab_obj:
            top_level_target_tab_id = default_tab_obj.id
            top_level_target_tab_name = default_tab_obj.name
        else: # No tabs exist at all, create a default one
            logger.info("OPML import: No tabs exist. Creating a default tab for top-level feeds.")
            default_tab_name_for_creation = "Imported Feeds"
            was_default_tab_created_for_this_import = False # Flag
            # Check if "Imported Feeds" tab was somehow created by a concurrent request (unlikely)
            temp_tab_check = Tab.query.filter_by(name=default_tab_name_for_creation).first()
            if temp_tab_check:
                top_level_target_tab_id = temp_tab_check.id
                top_level_target_tab_name = temp_tab_check.name
            else:
                newly_created_default_tab = Tab(name=default_tab_name_for_creation, order=0)
                db.session.add(newly_created_default_tab)
                try:
                    db.session.commit()
                    logger.info(f"OPML import: Created new default tab '{newly_created_default_tab.name}' (ID: {newly_created_default_tab.id}).")
                    invalidate_tabs_cache() # New tab added
                    top_level_target_tab_id = newly_created_default_tab.id
                    top_level_target_tab_name = newly_created_default_tab.name
                    was_default_tab_created_for_this_import = True # Mark that we created it
                except Exception as e_tab_commit:
                    db.session.rollback()
                    logger.error(f"OPML import: Failed to create default tab '{default_tab_name_for_creation}': {e_tab_commit}", exc_info=True)
                    return jsonify({'error': 'Failed to create a default tab for import.'}), 500

    if not top_level_target_tab_id: # Should be impossible if above logic is correct
         logger.error("OPML import: Critical error - failed to determine a top-level target tab.")
         return jsonify({'error': 'Failed to determine a target tab for import.'}), 500

    # --- Pre-fetch all existing feed URLs for efficient duplicate checking ---
    all_existing_feed_urls_set = {feed.url for feed in Feed.query.all()}

    # --- Process OPML ---
    opml_body = root.find('body')
    if opml_body is None:
        logger.warning("OPML import: No <body> element found in OPML file.")
        # Return early if no body, but use the determined/created tab name in message
        return jsonify({'message': 'No feeds found in OPML (missing body).', 'imported_count': 0, 'skipped_count': 0, 'tab_id': top_level_target_tab_id, 'tab_name': top_level_target_tab_name }), 200

    _process_opml_outlines_recursive(
        opml_body.findall('outline'),
        top_level_target_tab_id,
        top_level_target_tab_name,
        all_existing_feed_urls_set,
        newly_added_feeds_list,
        imported_count_wrapper,
        skipped_count_wrapper,
        affected_tab_ids_set
    )

    imported_final_count = imported_count_wrapper[0]
    skipped_final_count = skipped_count_wrapper[0]

    # --- Commit all newly added feeds and fetch their items ---
    if newly_added_feeds_list:
        try:
            # The main commit for all collected feeds happens here
            db.session.commit()
            logger.info(f"OPML import: Successfully batch-committed {len(newly_added_feeds_list)} new feeds to the database.")

            # Fetch items for these newly committed feeds
            logger.info(f"OPML import: Attempting to fetch initial items for {len(newly_added_feeds_list)} newly added feeds.")
            for feed_obj in newly_added_feeds_list: # These objects should now have IDs
                if feed_obj.id: # Should always be true after successful commit
                    try:
                        fetch_and_update_feed(feed_obj.id)
                    except Exception as fetch_e:
                        logger.error(f"OPML import: Error fetching items for new feed {feed_obj.name} (ID: {feed_obj.id}): {fetch_e}", exc_info=True)
                else: # Should not happen
                     logger.error(f"OPML import: Feed '{feed_obj.name}' missing ID after batch commit, cannot fetch items.")
            logger.info(f"OPML import: Finished attempting to fetch initial items for new feeds.")
        except Exception as e_commit_feeds:
            db.session.rollback()
            logger.error(f"OPML import: Database commit failed for new feeds: {e_commit_feeds}", exc_info=True)
            return jsonify({'error': 'Database error during final feed import step.'}), 500

    # --- Final cache invalidations for affected feed tabs ---
    # invalidate_tabs_cache() would have been called if new tabs were created.
    # Now, invalidate caches for all tabs that had feeds added to them.
    if affected_tab_ids_set: # If any feeds were added to any tabs
        invalidate_tabs_cache() # Invalidate main tabs list for unread counts anyway
        for tab_id_to_invalidate in affected_tab_ids_set:
            invalidate_tab_feeds_cache(tab_id_to_invalidate)
        logger.info(f"OPML import: Feed-related caches invalidated for tabs: {affected_tab_ids_set}.")

    if not opml_body.findall('outline') and not newly_added_feeds_list:
         logger.info("OPML import: No <outline> elements found in the OPML body to process as feeds or folders.")
         return jsonify({'message': 'No feed entries or folders found in the OPML file.', 'imported_count': 0, 'skipped_count': skipped_final_count, 'tab_id': top_level_target_tab_id, 'tab_name': top_level_target_tab_name}), 200

    # --- Check if the "Imported Feeds" tab (if created by this import) is empty ---
    # This check is relevant only if:
    # 1. A tab named "Imported Feeds" was created *during this specific import operation*.
    # 2. This "Imported Feeds" tab is also the `top_level_target_tab_id` (meaning it was the default for loose feeds).
    # 3. No feeds were actually added to it (all feeds went into folders/other tabs).
    if 'was_default_tab_created_for_this_import' in locals() and \
       was_default_tab_created_for_this_import and \
       top_level_target_tab_name == "Imported Feeds" and \
       top_level_target_tab_id not in affected_tab_ids_set:

        # Verify it's truly empty (no feeds associated with it from any source)
        # This is a defensive check; `top_level_target_tab_id not in affected_tab_ids_set` should suffice
        # if `affected_tab_ids_set` correctly tracks all tabs that received feeds.
        feeds_in_default_tab = Feed.query.filter_by(tab_id=top_level_target_tab_id).count()
        if feeds_in_default_tab == 0:
            logger.info(f"OPML import: The default 'Imported Feeds' tab (ID: {top_level_target_tab_id}) created during this import is empty. Deleting it.")
            try:
                tab_to_delete = db.session.get(Tab, top_level_target_tab_id)
                if tab_to_delete: # Should exist
                    db.session.delete(tab_to_delete)
                    db.session.commit()
                    invalidate_tabs_cache() # Cache needs update as a tab was removed
                    logger.info(f"OPML import: Successfully deleted empty 'Imported Feeds' tab (ID: {top_level_target_tab_id}).")
                    # If this deleted tab was the only tab, the frontend will create a new default tab on next load if needed.
                    # Or, if other tabs exist (e.g. from OPML folders), one of them will become active.
                    # We don't need to explicitly return a different tab_id here; the frontend will adapt.
                    # However, the original top_level_target_tab_id/name might now be misleading if returned.
                    # For simplicity, we'll still return them, but they refer to a now-deleted tab.
                    # The frontend should handle this gracefully.
                else:
                    logger.warning(f"OPML import: Tried to delete empty 'Imported Feeds' tab (ID: {top_level_target_tab_id}), but it was not found in session.")
            except Exception as e_del_tab:
                db.session.rollback()
                logger.error(f"OPML import: Failed to delete empty 'Imported Feeds' tab (ID: {top_level_target_tab_id}): {e_del_tab}", exc_info=True)
        else:
            logger.info(f"OPML import: The default 'Imported Feeds' tab (ID: {top_level_target_tab_id}) was created but contains {feeds_in_default_tab} feeds. It will not be deleted.")


    return jsonify({
        'message': f'{imported_final_count} feeds imported. {skipped_final_count} feeds skipped. Feeds were imported into relevant tabs or default tab "{top_level_target_tab_name}".',
        'imported_count': imported_final_count,
        'skipped_count': skipped_final_count,
        'tab_id': top_level_target_tab_id,      # This might be the ID of a tab that was just deleted if it was the empty "Imported Feeds"
        'tab_name': top_level_target_tab_name  # Same as above
    }), 200

# --- Tabs API Endpoints ---

@app.route('/api/tabs', methods=['GET'])
@cache.cached(make_cache_key=make_tabs_cache_key)
def get_tabs():
    """Returns a list of all tabs, ordered by their 'order' field.

    Returns:
        A JSON response containing a list of tab objects.
    """
    tabs = Tab.query.order_by(Tab.order).all()
    return jsonify([tab.to_dict() for tab in tabs])

@app.route('/api/tabs', methods=['POST'])
def create_tab():
    """Creates a new tab.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    data = request.get_json()
    # Validate input data
    if not data or 'name' not in data or not data['name'].strip():
        return jsonify({'error': 'Missing or empty tab name'}), 400

    tab_name = data['name'].strip()

    # Check for duplicate tab name
    existing_tab = Tab.query.filter_by(name=tab_name).first()
    if existing_tab:
        return jsonify({'error': f'Tab with name "{tab_name}" already exists'}), 409 # Conflict

    # Determine the order for the new tab (append to the end)
    max_order = db.session.query(db.func.max(Tab.order)).scalar()
    new_order = (max_order or -1) + 1

    try:
        new_tab = Tab(name=tab_name, order=new_order)
        db.session.add(new_tab)
        db.session.commit()
        invalidate_tabs_cache()
        logger.info(f"Created new tab '{new_tab.name}' with id {new_tab.id}.")
        return jsonify(new_tab.to_dict()), 201 # Created
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating tab '{tab_name}': {str(e)}", exc_info=True)
        # Let the 500 handler manage the response
        raise e

@app.route('/api/tabs/<int:tab_id>', methods=['PUT'])
def rename_tab(tab_id):
    """Renames an existing tab.

    Args:
        tab_id (int): The ID of the tab to rename.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find the tab or return 404
    tab = db.get_or_404(Tab, tab_id)

    data = request.get_json()
    # Validate input data
    if not data or 'name' not in data or not data['name'].strip():
        return jsonify({'error': 'Missing or empty new tab name'}), 400

    new_name = data['name'].strip()

    # Check if the new name is already taken by another tab
    existing_tab = Tab.query.filter(Tab.id != tab_id, Tab.name == new_name).first()
    if existing_tab:
        return jsonify({'error': f'Tab name "{new_name}" is already in use'}), 409 # Conflict

    try:
        original_name = tab.name
        tab.name = new_name
        db.session.commit()
        invalidate_tabs_cache()
        logger.info(f"Renamed tab {tab_id} from '{original_name}' to '{new_name}'.")
        return jsonify(tab.to_dict()), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error renaming tab {tab_id} to '{new_name}': {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

@app.route('/api/tabs/<int:tab_id>', methods=['DELETE'])
def delete_tab(tab_id):
    """Deletes a tab and its associated feeds/items."""
    # Find the tab or return 404
    tab = db.get_or_404(Tab, tab_id)

    # Removed: Prevent deleting the last remaining tab. Frontend now controls this.
    # if Tab.query.count() <= 1:
    #     return jsonify({'error': 'Cannot delete the last tab'}), 400

    try:
        tab_name = tab.name
        # Associated feeds/items are deleted due to cascade settings in the model
        db.session.delete(tab)
        db.session.commit()
        invalidate_tabs_cache()
        logger.info(f"Deleted tab '{tab_name}' with id {tab_id}.")
        return jsonify({'message': f'Tab {tab_id} deleted successfully'}), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting tab {tab_id}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

# --- Feeds API Endpoints ---

@app.route('/api/tabs/<int:tab_id>/feeds', methods=['GET'])
@cache.cached(make_cache_key=make_tab_feeds_cache_key)
def get_feeds_for_tab(tab_id):
    """
    Returns a list of feeds for a tab, including recent items for each feed.
    This is highly optimized to prevent the N+1 query problem.
    """
    # Ensure tab exists, or return 404.
    db.get_or_404(Tab, tab_id)

    # Get limit for items from query string, default to DEFAULT_FEED_ITEMS_LIMIT.
    limit = request.args.get('limit', DEFAULT_FEED_ITEMS_LIMIT, type=int)

    # Query 1: Get all feeds for the given tab.
    feeds = Feed.query.filter_by(tab_id=tab_id).all()
    if not feeds:
        return jsonify([])

    feed_ids = [feed.id for feed in feeds]

    # Query 2: Get the top N items for ALL those feeds in a single, efficient query.
    # Use a window function to rank items within each feed.
    ranked_items_subq = select(
        FeedItem,
        func.row_number().over(
            partition_by=FeedItem.feed_id,
            order_by=[FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()]
        ).label('rank')
    ).filter(FeedItem.feed_id.in_(feed_ids)).subquery()

    # Select from the subquery to filter by the rank.
    top_items_query = select(ranked_items_subq).filter(ranked_items_subq.c.rank <= limit)
    
    top_items_results = db.session.execute(top_items_query).all()

    # Group the fetched items by feed_id for efficient lookup.
    items_by_feed = {}
    for item_row in top_items_results:
        # Directly serialize the row to a dict, avoiding ORM object creation.
        item_dict = {
            'id': item_row.id,
            'feed_id': item_row.feed_id,
            'title': item_row.title,
            'link': item_row.link,
            'published_time': FeedItem.to_iso_z_string(item_row.published_time),
            'fetched_time': FeedItem.to_iso_z_string(item_row.fetched_time),
            'is_read': item_row.is_read,
            'guid': item_row.guid
        }
        
        feed_id = item_row.feed_id
        if feed_id not in items_by_feed:
            items_by_feed[feed_id] = []
        items_by_feed[feed_id].append(item_dict)

    # Build the final response, combining feeds with their items.
    response_data = []
    for feed in feeds:
        feed_dict = feed.to_dict()
        feed_dict['items'] = items_by_feed.get(feed.id, [])
        response_data.append(feed_dict)

    return jsonify(response_data)

@app.route('/api/feeds', methods=['POST'])
def add_feed():
    """Adds a new feed to a specified tab (or the default tab)."""
    data = request.get_json()
    # Validate input
    if not data or 'url' not in data or not data['url'].strip():
        return jsonify({'error': 'Missing feed URL'}), 400

    feed_url = data['url'].strip()
    tab_id = data.get('tab_id') # Optional tab ID

    # Determine target tab ID
    if not tab_id:
        # Find the first tab by order if no ID provided
        default_tab = Tab.query.order_by(Tab.order).first()
        if not default_tab:
            # Cannot add feed if no tabs exist
            return jsonify({'error': 'Cannot add feed: No default tab found'}), 400
        tab_id = default_tab.id
    else:
        # Verify the provided tab_id exists
        tab = db.session.get(Tab, tab_id)
        if not tab:
            return jsonify({'error': f'Tab with id {tab_id} not found'}), 404

    # Check if feed URL already exists in the database
    existing_feed = Feed.query.filter_by(url=feed_url).first()
    if existing_feed:
        return jsonify({'error': f'Feed with URL {feed_url} already exists'}), 409 # Conflict

    # Attempt to fetch the feed to get its title
    parsed_feed = fetch_feed(feed_url)
    if not parsed_feed or not parsed_feed.feed:
        # If fetch fails initially, use the URL as the name
        feed_name = feed_url
        site_link = None # No website link if fetch failed
        logger.warning(f"Could not fetch title for {feed_url}, using URL as name.")
    else:
        feed_name = parsed_feed.feed.get('title', feed_url) # Use URL as fallback if title missing
        site_link = parsed_feed.feed.get('link') # Get the website link

    try:
        # Create and save the new feed
        new_feed = Feed(
            tab_id=tab_id,
            name=feed_name,
            url=feed_url,
            site_link=site_link
            # last_updated_time defaults to now
        )
        db.session.add(new_feed)
        db.session.commit() # Commit to get the new_feed.id
        
        # Trigger initial fetch and processing of items for the new feed
        num_new_items = 0
        if parsed_feed:
            try:
                num_new_items = process_feed_entries(new_feed, parsed_feed)
                logger.info(f"Processed initial {num_new_items} items for feed {new_feed.id}")
            except Exception as proc_e:
                # Log error during initial processing but don't fail the add operation
                logger.error(f"Error processing initial items for feed {new_feed.id}: {proc_e}", exc_info=True)
        
        if num_new_items > 0:
            invalidate_tab_feeds_cache(tab_id)
        else:
            invalidate_tabs_cache() # At least invalidate for unread count change potential
        
        logger.info(f"Added new feed '{new_feed.name}' with id {new_feed.id} to tab {tab_id}.")
        return jsonify(new_feed.to_dict()), 201 # Created

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding feed {feed_url}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

@app.route('/api/feeds/<int:feed_id>', methods=['DELETE'])
def delete_feed(feed_id):
    """Deletes a feed and its associated items.

    Args:
        feed_id (int): The ID of the feed to delete.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find feed or return 404
    feed = db.get_or_404(Feed, feed_id)
    try:
        tab_id = feed.tab_id
        feed_name = feed.name
        # Associated items are deleted due to cascade settings
        db.session.delete(feed)
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id)
        logger.info(f"Deleted feed '{feed_name}' with id {feed_id}.")
        return jsonify({'message': f'Feed {feed_id} deleted successfully'}), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting feed {feed_id}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

@app.route('/api/feeds/<int:feed_id>', methods=['PUT'])
def update_feed_url(feed_id):
    """Updates a feed's URL and name.

    Args:
        feed_id (int): The ID of the feed to update.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find feed or return 404
    feed = db.get_or_404(Feed, feed_id)
    
    data = request.get_json()
    # Validate input
    if not data or 'url' not in data or not (isinstance(data['url'], str) and data['url'].strip()):
        return jsonify({'error': 'Missing or invalid feed URL'}), 400
    
    new_url = data['url'].strip()
    
    # Check if the new URL is already used by another feed
    existing_feed = Feed.query.filter(Feed.id != feed_id, Feed.url == new_url).first()
    if existing_feed:
        return jsonify({'error': f'Feed with URL {new_url} already exists'}), 409 # Conflict
    
    try:
        # Attempt to fetch the feed to get its title
        parsed_feed = fetch_feed(new_url)
        if not parsed_feed or not parsed_feed.feed:
            # If fetch fails, use the URL as the name
            new_name = new_url
            new_site_link = None
            logger.warning(f"Could not fetch title for {new_url}, using URL as name.")
        else:
            new_name = parsed_feed.feed.get('title', new_url) # Use URL as fallback if title missing
            new_site_link = parsed_feed.feed.get('link') # Get the website link
        
        # Update the feed
        original_url = feed.url
        feed.url = new_url
        feed.name = new_name
        feed.site_link = new_site_link
        feed.last_updated_time = datetime.datetime.now(datetime.timezone.utc)
        
        db.session.commit()
        
        # Invalidate cache for the feed's tab, as feed properties (name, url) have changed.
        invalidate_tab_feeds_cache(feed.tab_id)
        logger.info(f"Cache invalidated for tab {feed.tab_id} after updating feed {feed.id}.")

        # Trigger update to fetch new items using the already fetched feed data
        try:
            if parsed_feed:
                # Reuse the already fetched and parsed feed data to process entries,
                # avoiding a redundant network call.
                process_feed_entries(feed, parsed_feed)
        except Exception as update_e:
            # Log error during update but don't fail the operation
            logger.error(f"Error updating feed {feed.id} after URL change: {update_e}", exc_info=True)
        
        logger.info(f"Updated feed {feed_id} from '{original_url}' to '{new_url}'.")
        
        # Return full feed data including items for frontend to update widget
        feed_data = feed.to_dict()
        # Include only recent feed items in the response (limit to DEFAULT_FEED_ITEMS_LIMIT)
        feed_data['items'] = [item.to_dict() for item in feed.items.order_by(FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()).limit(DEFAULT_FEED_ITEMS_LIMIT)]
        return jsonify(feed_data), 200 # OK
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating feed {feed_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to update feed URL'}), 500

# --- Feed Items API Endpoints ---

@app.route('/api/items/<int:item_id>/read', methods=['POST'])
def mark_item_read(item_id):
    """Marks a specific feed item as read.

    Args:
        item_id (int): The ID of the feed item to mark as read.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find item or return 404
    item = db.session.get(FeedItem, item_id)
    if not item:
        return jsonify({'error': 'Feed item not found'}), 404

    # If already read, return success without changing anything
    if item.is_read:
        return jsonify({'message': 'Item already marked as read'}), 200 # OK

    try:
        tab_id = item.feed.tab_id
        item.is_read = True
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id)
        logger.info(f"Marked item {item_id} as read.")
        return jsonify({'message': f'Item {item_id} marked as read'}), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marking item {item_id} as read: {str(e)}", exc_info=True)
        # Let 500 handler manage response (or return specific error)
        return jsonify({'error': 'Failed to mark item as read'}), 500

# --- Manual Feed Update Endpoint ---

@app.route('/api/feeds/update-all', methods=['POST'])
def api_update_all_feeds():
    """Triggers an update for all feeds in the system.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    logger.info("Received request to update all feeds.")
    try:
        processed_count, new_items_count = update_all_feeds()
        logger.info(f"All feeds update process completed. Processed: {processed_count}, New Items: {new_items_count}")
        if new_items_count > 0:
            cache.clear()
            logger.info("Cache cleared after manual 'update-all' found new items.")
        # Announce the update to listening clients
        event_data = {'feeds_processed': processed_count, 'new_items': new_items_count}
        msg = f"data: {json.dumps(event_data)}\n\n"
        announcer.announce(msg=msg)
        return jsonify({
            'message': 'All feeds updated successfully.',
            'feeds_processed': processed_count,
            'new_items': new_items_count
        }), 200
    except Exception as e:
        logger.error(f"Error during /api/feeds/update-all: {str(e)}", exc_info=True)
        # Consistent error response with other parts of the API
        return jsonify({'error': 'An error occurred while updating all feeds.'}), 500

@app.route('/api/feeds/<int:feed_id>/update', methods=['POST'])
def update_feed(feed_id):
    """Manually triggers an update check for a specific feed."""
    feed = db.get_or_404(Feed, feed_id)
    try:
        success, new_items = fetch_and_update_feed(feed.id)
        if success and new_items > 0:
            invalidate_tab_feeds_cache(feed.tab_id)
            logger.info(f"Cache invalidated for tab {feed.tab_id} after manual update of feed {feed.id}.")
        
        return jsonify(feed.to_dict())
    except Exception as e:
        logger.error(f"Error during manual update for feed {feed.id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to update feed {feed.id}. An unexpected error occurred.'}), 500

@app.route('/api/feeds/<int:feed_id>/items', methods=['GET'])
def get_feed_items(feed_id):
    """Returns a paginated list of items for a specific feed."""
    # Ensure the feed exists, or return a 404 error
    db.get_or_404(Feed, feed_id)

    # Get offset and limit from the request's query string, with default values
    try:
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', DEFAULT_PAGINATION_LIMIT))
    except (ValueError, TypeError):
        return jsonify({'error': 'Offset and limit parameters must be valid integers.'}), 400

    # Validate and cap pagination parameters
    if offset < 0:
        return jsonify({'error': 'Offset cannot be negative.'}), 400
    if limit <= 0:
        return jsonify({'error': 'Limit must be positive.'}), 400
    limit = min(limit, MAX_PAGINATION_LIMIT)

    # Query the database for the items, ordered by date
    items = FeedItem.query.filter_by(feed_id=feed_id)\
        .order_by(FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc())\
        .offset(offset)\
        .limit(limit)\
        .all()

    # Return the items as a JSON response
    return jsonify([item.to_dict() for item in items])

# --- Application Initialization and Startup ---

if __name__ == '__main__':
    # Start the Flask development server for local testing.
    # The scheduler is already started in the global scope.
    is_debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    logger.info(f"Starting Flask app (Debug mode: {is_debug_mode})")
    app.run(host='0.0.0.0', port=5001, debug=is_debug_mode)
    
    logger.info("SheepVibes application finished.")
