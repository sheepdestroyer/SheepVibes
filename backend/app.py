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
from flask_caching import Cache # Added for caching

# Import db object and models from the new models.py
from .models import db, Tab, Feed, FeedItem
from .opml_utils import parse_opml, generate_opml # Added for OPML import and export
from sqlalchemy.orm import joinedload # Added for eager loading for OPML export

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
    """A simple message announcer that uses server-sent events."""
    def __init__(self):
        self.listeners = []

    def listen(self):
        """
        Listens for messages, yielding them to the client.
        This is a generator function that maintains a connection.
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
        """Announces a message to all listeners."""
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

# Configure SQLite database URI
# Use environment variable DATABASE_PATH or default to the standard path inside the container
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
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable modification tracking

# --- Cache Configuration ---
app.config["CACHE_TYPE"] = "RedisCache"
app.config["CACHE_REDIS_URL"] = os.environ.get("CACHE_REDIS_URL", "redis://localhost:6379/0")
app.config['CACHE_DEFAULT_TIMEOUT'] = 300 # 5 minutes default timeout

cache = Cache()

# Initialize SQLAlchemy ORM extension with the app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize the cache with the app config
cache.init_app(app)

# --- Cache Key Generation and Invalidation ---

def get_version(key, default=1):
    """Gets a version number for a cache key from the cache."""
    return cache.get(key) or default

def make_tabs_cache_key(*args, **kwargs):
    """Creates a cache key for the main tabs list, incorporating a version."""
    version = get_version('tabs_version')
    return f'view/tabs/v{version}'

def make_tab_feeds_cache_key(tab_id):
    """Creates a cache key for a specific tab's feeds, incorporating version and query params."""
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
    """Invalidates a specific tab's feed cache and the main tabs list cache."""
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
# Ensure the scheduler doesn't start if the app is being run by Flask's reloader in debug mode,
# as that can lead to multiple schedulers.
if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    try:
        scheduler.start()
        # Ensure shutdown is registered only once
        if not hasattr(atexit, '_registered_scheduler_shutdown'):
            atexit.register(lambda: scheduler.shutdown())
            setattr(atexit, '_registered_scheduler_shutdown', True) # Use setattr for safety
        logger.info("Background scheduler started.")
    except (KeyboardInterrupt, SystemExit): # Handle cases where the app is shut down abruptly
        logger.info("Scheduler shutdown requested via KeyboardInterrupt/SystemExit.")
        if scheduler.running:
             scheduler.shutdown()
    except Exception as e: # Catch other potential errors during scheduler start
        logger.error(f"Failed to start the background scheduler: {e}", exc_info=True)
else:
    logger.info("Background scheduler not started in Flask debug reloader process.")


# --- Error Handlers ---

@app.errorhandler(404)
def not_found_error(error):
    """Handles 404 Not Found errors with a JSON response."""
    logger.warning(f"404 Not Found: {request.path}")
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handles 500 Internal Server Errors with a JSON response and logs the error."""
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
    """Serves static files like CSS and JS from the frontend folder."""
    # Basic security check: prevent accessing files outside the frontend folder
    if ".." in filename or filename.startswith("/"):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory(FRONTEND_FOLDER, filename)

# --- SSE Stream Endpoint ---
@app.route('/api/stream')
def stream():
    """Endpoint for Server-Sent Events (SSE) to stream updates."""
    return Response(announcer.listen(), mimetype='text/event-stream')

# --- Tabs API Endpoints ---

@app.route('/api/tabs', methods=['GET'])
@cache.cached(make_cache_key=make_tabs_cache_key)
def get_tabs():
    """Returns a list of all tabs, ordered by their 'order' field."""
    tabs = Tab.query.order_by(Tab.order).all()
    return jsonify([tab.to_dict() for tab in tabs])

@app.route('/api/tabs', methods=['POST'])
def create_tab():
    """Creates a new tab."""
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
        raise # Reraise the original exception

@app.route('/api/tabs/<int:tab_id>', methods=['PUT'])
def rename_tab(tab_id):
    """Renames an existing tab."""
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
        raise # Reraise

@app.route('/api/tabs/<int:tab_id>', methods=['DELETE'])
def delete_tab(tab_id):
    """Deletes a tab and its associated feeds/items."""
    # Find the tab or return 404
    tab = db.get_or_404(Tab, tab_id)

    # Prevent deleting the last remaining tab
    if Tab.query.count() <= 1:
        return jsonify({'error': 'Cannot delete the last tab'}), 400

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
        raise # Reraise

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

    # Get limit for items from query string, default to 10.
    limit = request.args.get('limit', 10, type=int)

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
        logger.warning(f"Could not fetch title for {feed_url}, using URL as name.")
    else:
        feed_name = parsed_feed.feed.get('title', feed_url) # Use URL as fallback if title missing

    try:
        # Create and save the new feed
        new_feed = Feed(
            tab_id=tab_id,
            name=feed_name,
            url=feed_url
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
        raise # Reraise

@app.route('/api/feeds/<int:feed_id>', methods=['DELETE'])
def delete_feed(feed_id):
    """Deletes a feed and its associated items."""
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
        raise # Reraise

# --- OPML Import Endpoint ---

@app.route('/api/opml/import', methods=['POST'])
def opml_import():
    """Imports feeds from an OPML file."""
    if 'file' not in request.files:
        logger.warning("OPML import attempt with no file part.")
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        logger.warning("OPML import attempt with no selected file.")
        return jsonify({'error': 'No selected file'}), 400

    if not file or not file.filename.lower().endswith('.opml'):
        logger.warning(f"OPML import attempt with invalid file type: {file.filename}")
        return jsonify({'error': 'Invalid file type. Please upload an OPML file.'}), 400

    try:
        # Read as bytes first to handle potential encoding issues, then decode
        opml_bytes = file.read()
        opml_content = opml_bytes.decode('utf-8')
    except UnicodeDecodeError:
        logger.warning(f"OPML file {file.filename} is not UTF-8 encoded. Attempting latin-1.")
        try:
            opml_content = opml_bytes.decode('latin-1') # Common fallback
        except Exception as e:
            logger.error(f"Error reading or decoding OPML file {file.filename}: {e}", exc_info=True)
            return jsonify({'error': 'Error reading or decoding OPML file. Ensure it is UTF-8 or Latin-1 encoded.'}), 500
    except Exception as e:
        logger.error(f"Error reading OPML file {file.filename}: {e}", exc_info=True)
        return jsonify({'error': 'Error reading OPML file'}), 500

    if not opml_content.strip():
        logger.warning("OPML import attempt with empty file content.")
        return jsonify({'error': 'OPML file is empty'}), 400

    try:
        parsed_feeds = parse_opml(opml_content)
    except Exception as e: # Catching broad exception from parse_opml itself
        logger.error(f"Error parsing OPML content from file {file.filename}: {e}", exc_info=True)
        return jsonify({'error': f'Error parsing OPML file: {str(e)}'}), 500

    if not parsed_feeds:
        logger.info(f"OPML file {file.filename} parsed, but no feeds found or it contained no valid feed entries.")
        return jsonify({'message': 'OPML processed, but no new feeds to import.', 'new_feeds_added': 0, 'new_tabs_created': 0}), 200

    logger.info(f"Successfully parsed OPML file {file.filename}. Found {len(parsed_feeds)} potential feeds.")

    new_feeds_count = 0
    new_tabs_count = 0
    affected_tab_ids = set()
    default_tab_name = "Imported Feeds" # Default tab name if not specified in OPML

    try:
        for feed_data in parsed_feeds:
            xml_url = feed_data.get('xmlUrl')
            feed_title = feed_data.get('title')
            # Use 'outline' value for tab name, fallback to default_tab_name if empty or not present
            outline_name = feed_data.get('outline') if feed_data.get('outline') and feed_data.get('outline').strip() else default_tab_name

            if not xml_url:
                logger.warning(f"Skipping feed due to missing xmlUrl in OPML entry: {feed_data}")
                continue

            # Find or create Tab
            tab = Tab.query.filter_by(name=outline_name).first()
            if not tab:
                max_order = db.session.query(db.func.max(Tab.order)).scalar()
                new_order = (max_order or -1) + 1
                tab = Tab(name=outline_name, order=new_order)
                db.session.add(tab)
                db.session.flush()
                new_tabs_count += 1
                logger.info(f"Creating new tab '{outline_name}' (ID: {tab.id}) for OPML import.")

            affected_tab_ids.add(tab.id)

            # Check if Feed already exists by URL (globally)
            existing_feed = Feed.query.filter_by(url=xml_url).first()
            if not existing_feed:
                new_feed_name = feed_title if feed_title and feed_title.strip() else xml_url

                if new_feed_name == xml_url: # Indicates original title was missing or empty
                    try:
                        parsed_feed_info = fetch_feed(xml_url)
                        if parsed_feed_info and parsed_feed_info.feed:
                            fetched_title = parsed_feed_info.feed.get('title')
                            if fetched_title and fetched_title.strip():
                                new_feed_name = fetched_title
                    except Exception as fetch_exc:
                        logger.warning(f"Could not fetch title for {xml_url} during OPML import: {fetch_exc}. Using URL as name.")

                feed = Feed(name=new_feed_name, url=xml_url, tab_id=tab.id)
                db.session.add(feed)
                new_feeds_count += 1
                logger.info(f"Adding new feed '{new_feed_name}' ({xml_url}) to tab '{tab.name}' (ID: {tab.id}) from OPML.")
            else:
                logger.info(f"Feed with URL '{xml_url}' already exists (ID: {existing_feed.id} in Tab ID: {existing_feed.tab_id}), skipping.")

        if new_feeds_count > 0 or new_tabs_count > 0:
            db.session.commit()
            logger.info(f"OPML import successful from file {file.filename}: {new_feeds_count} new feeds added, {new_tabs_count} new tabs created.")
            for tab_id_iter in affected_tab_ids:
                invalidate_tab_feeds_cache(tab_id_iter)
            if not affected_tab_ids and new_tabs_count > 0 :
                 invalidate_tabs_cache()

        return jsonify({
            'message': 'OPML import processed successfully.',
            'new_feeds_added': new_feeds_count,
            'new_tabs_created': new_tabs_count
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error during OPML import from file {file.filename}: {e}", exc_info=True)
        return jsonify({'error': 'An error occurred while saving imported feeds to the database.'}), 500

# --- Feed Items API Endpoints ---

# --- OPML Export Endpoint ---
@app.route('/api/opml/export', methods=['GET'])
def opml_export():
    """Exports all tabs and feeds as an OPML file."""
    try:
        # Fetch all tabs and eagerly load their associated feeds
        # Order by Tab.order and then by Feed.id (or Feed.name) for consistent output
        tabs_with_feeds = Tab.query.options(
            joinedload(Tab.feeds)
        ).order_by(Tab.order).all()

        # It's good practice to also order feeds within each tab if generate_opml doesn't handle it
        # However, generate_opml iterates over tab.feeds which should be ordered if Tab.feeds relationship has an order_by
        # If not, and order is important, feeds might need sorting here or in generate_opml
        # For now, assume default order or order by ID from DB is sufficient.

        if not tabs_with_feeds:
            logger.info("OPML Export: No tabs found to export.")
            # Return an empty OPML structure or a message
            empty_opml_xml = generate_opml([]) # Assuming generate_opml can handle empty list
            return Response(empty_opml_xml, mimetype='application/xml', headers={'Content-Disposition': 'attachment; filename=sheepvibes_empty.opml'})

        opml_xml_string = generate_opml(tabs_with_feeds)

        logger.info(f"Successfully generated OPML for {len(tabs_with_feeds)} tabs.")

        return Response(
            opml_xml_string,
            mimetype='application/xml',
            headers={'Content-Disposition': 'attachment; filename=sheepvibes_feeds.opml'}
        )
    except Exception as e:
        logger.error(f"Error during OPML export: {e}", exc_info=True)
        # Let the global 500 error handler manage the response
        # but provide a more specific JSON error if possible for API consistency
        return jsonify({'error': f'Failed to generate OPML export: {str(e)}'}), 500


@app.route('/api/items/<int:item_id>/read', methods=['POST'])
def mark_item_read(item_id):
    """Marks a specific feed item as read."""
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
    """
    Triggers an update for all feeds in the system.
    Returns the count of processed feeds and new items.
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

# --- Application Initialization and Startup ---

if __name__ == '__main__':
    # Start the Flask development server for local testing.
    # The scheduler is started above, considering debug mode.
    # Determine debug mode status from Flask app config or environment variable.
    is_debug_mode = app.debug or os.environ.get('FLASK_DEBUG', '0') == '1'

    if __name__ == '__main__':
        # This block runs when the script is executed directly (e.g., `python -m backend.app`)
        logger.info(f"Starting Flask development server on http://0.0.0.0:5000 (Debug: {is_debug_mode})")
        # The `WERKZEUG_RUN_MAIN` check for scheduler start should handle reloader.
        app.run(host='0.0.0.0', port=5000, debug=is_debug_mode)
        logger.info("SheepVibes Flask development server stopped.")
    else:
        # This block runs if imported by a WSGI server like Gunicorn
        # Gunicorn will handle starting the app, so no app.run() here.
        # Scheduler should have been started above if not in Werkzeug reloader process.
        logger.info("SheepVibes application configured and ready for WSGI server.")
