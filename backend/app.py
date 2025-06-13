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
# Use a simple in-memory cache. For multi-worker setups, each worker gets its own cache.
# For shared cache, use 'redis' or 'memcached'.
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300 # 5 minutes default timeout

cache = Cache(app)

# Initialize SQLAlchemy ORM extension with the app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# --- Database Models have been moved to models.py ---


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
            cache.clear()
            logger.info("Cache cleared after scheduled update.")
            
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
@cache.cached()
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
        cache.clear()
        logger.info(f"Created new tab '{new_tab.name}' with id {new_tab.id}, cache cleared.")
        return jsonify(new_tab.to_dict()), 201 # Created
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating tab '{tab_name}': {str(e)}", exc_info=True)
        # Let the 500 handler manage the response
        raise e

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
        cache.clear()
        logger.info(f"Renamed tab {tab_id} from '{original_name}' to '{new_name}', cache cleared.")
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

    # Prevent deleting the last remaining tab
    if Tab.query.count() <= 1:
        return jsonify({'error': 'Cannot delete the last tab'}), 400

    try:
        tab_name = tab.name
        # Associated feeds/items are deleted due to cascade settings in the model
        db.session.delete(tab)
        db.session.commit()
        cache.clear()
        logger.info(f"Deleted tab '{tab_name}' with id {tab_id}, cache cleared.")
        return jsonify({'message': f'Tab {tab_id} deleted successfully'}), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting tab {tab_id}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

# --- Feeds API Endpoints ---

@app.route('/api/tabs/<int:tab_id>/feeds', methods=['GET'])
@cache.cached()
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
        cache.clear()
        logger.info(f"Added new feed '{new_feed.name}' with id {new_feed.id} to tab {tab_id}, cache cleared.")

        # Trigger initial fetch and processing of items for the new feed
        if parsed_feed:
            try:
                process_feed_entries(new_feed, parsed_feed)
                logger.info(f"Processed initial items for feed {new_feed.id}")
            except Exception as proc_e:
                # Log error during initial processing but don't fail the add operation
                logger.error(f"Error processing initial items for feed {new_feed.id}: {proc_e}", exc_info=True)
        
        return jsonify(new_feed.to_dict()), 201 # Created

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding feed {feed_url}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

@app.route('/api/feeds/<int:feed_id>', methods=['DELETE'])
def delete_feed(feed_id):
    """Deletes a feed and its associated items."""
    # Find feed or return 404
    feed = db.get_or_404(Feed, feed_id)
    try:
        feed_name = feed.name
        # Associated items are deleted due to cascade settings
        db.session.delete(feed)
        db.session.commit()
        cache.clear()
        logger.info(f"Deleted feed '{feed_name}' with id {feed_id}, cache cleared.")
        # Return 204 No Content might be more appropriate for DELETE
        # return '', 204
        return jsonify({'message': f'Feed {feed_id} deleted successfully'}), 200 # OK
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting feed {feed_id}: {str(e)}", exc_info=True)
        raise e # Let 500 handler manage response

# --- Feed Items API Endpoints ---

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
        item.is_read = True
        db.session.commit()
        cache.clear()
        logger.info(f"Marked item {item_id} as read, cache cleared.")
        # Return 204 No Content might be more appropriate
        # return '', 204
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
        cache.clear()
        logger.info("Cache cleared after manual 'update-all'.")
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
    try:
        updated_feed_obj = fetch_and_update_feed(feed_id)
        cache.clear()
        logger.info(f"Cache cleared after manual update for feed {feed_id}.")
        
        return jsonify(updated_feed_obj.to_dict())
    except LookupError as e:
        logger.warning(f"LookupError during manual update for feed {feed_id}: {e}")
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error during manual update for feed {feed_id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to update feed {feed_id}. An unexpected error occurred.'}), 500

# --- Application Initialization and Startup ---

if __name__ == '__main__':
    # Start the Flask development server for local testing.
    # The scheduler is already started in the global scope.
    is_debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    logger.info(f"Starting Flask app (Debug mode: {is_debug_mode})")
    app.run(host='0.0.0.0', port=5000, debug=is_debug_mode)
    
    logger.info("SheepVibes application finished.")
