import atexit
import json
import logging
import os

from filelock import FileLock
from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate

from .blueprints.feeds import feeds_bp, items_bp
from .blueprints.opml import autosave_opml, opml_bp
from .blueprints.tabs import tabs_bp
from .cache_utils import invalidate_tab_feeds_cache, invalidate_tabs_cache
from .constants import (
    OPML_AUTOSAVE_INTERVAL_MINUTES_DEFAULT,
    UPDATE_INTERVAL_MINUTES_DEFAULT,
)
from .extensions import cache, db, scheduler
from .feed_service import update_all_feeds
from .sse import announcer

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],  # Log to standard output
)
logger = logging.getLogger("sheepvibes")

# Initialize Flask application
app = Flask(__name__)
app.config["PROJECT_ROOT"] = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

# Configure CORS with specific allowed origins
allowed_origins_str = os.environ.get(
    "CORS_ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
)
allowed_origins = [
    origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()
]
CORS(app, origins=allowed_origins, resources={r"/api/*": {}})

# Test specific configuration
# Check app.config first in case it's set by test runner, then env var
if app.config.get("TESTING") or os.environ.get("TESTING") == "true":
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True  # Ensure it's explicitly True in app.config
    app.config["CACHE_TYPE"] = (
        "SimpleCache"  # Use SimpleCache for tests, no Redis needed
    )
    logger.info("TESTING mode: Using in-memory SQLite database and SimpleCache.")
else:
    # Existing database configuration logic
    default_db_path_in_container = "/app/data/sheepvibes.db"
    db_path_env = os.environ.get("DATABASE_PATH")

    if db_path_env:
        if db_path_env.startswith("sqlite:///"):
            app.config["SQLALCHEMY_DATABASE_URI"] = db_path_env
            logger.info(
                "Using DATABASE_PATH environment variable directly: %s", db_path_env
            )
        else:
            db_path = db_path_env
            app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
            logger.info(
                "Using DATABASE_PATH environment variable for file path: %s", db_path
            )
    else:
        # Default path logic
        if not os.path.exists("/app"):  # Assume local development
            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..")
            )
            local_data_dir = os.path.join(project_root, "data")
            os.makedirs(local_data_dir, exist_ok=True)
            db_path = os.path.join(local_data_dir, "sheepvibes.db")
            logger.info(
                "DATABASE_PATH not set, assuming local run. Using file path: %s",
                db_path,
            )
        else:  # Assume container run
            db_path = default_db_path_in_container
            logger.info(
                "DATABASE_PATH not set, assuming container run. Using default file path: %s",
                db_path,
            )
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

    # --- Cache Configuration for non-testing ---
    app.config["CACHE_TYPE"] = "RedisCache"
    app.config["CACHE_REDIS_URL"] = os.environ.get(
        "CACHE_REDIS_URL", "redis://localhost:6379/0"
    )

# Disable modification tracking
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
cache.init_app(app)

# Register Blueprints
app.register_blueprint(opml_bp)
app.register_blueprint(tabs_bp)
app.register_blueprint(feeds_bp)
app.register_blueprint(items_bp)

# --- Scheduler Configuration ---

UPDATE_INTERVAL_MINUTES = int(
    os.environ.get("UPDATE_INTERVAL_MINUTES", UPDATE_INTERVAL_MINUTES_DEFAULT)
)
OPML_AUTOSAVE_INTERVAL_MINUTES = int(
    os.environ.get(
        "OPML_AUTOSAVE_INTERVAL_MINUTES", OPML_AUTOSAVE_INTERVAL_MINUTES_DEFAULT
    )
)


@scheduler.scheduled_job("interval", minutes=UPDATE_INTERVAL_MINUTES, id="update_feeds")
def scheduled_feed_update():
    """Scheduled job to periodically update all feeds in the database."""
    # Use a file lock to ensure only one worker runs this job
    lock = FileLock("feed_update.lock")
    try:
        with lock.acquire(timeout=1):  # Non-blocking attempt
            # Need app context to access database within the scheduled job
            with app.app_context():
                logger.info(
                    "Running scheduled feed update (every %s minutes)",
                    UPDATE_INTERVAL_MINUTES,
                )
                try:
                    feeds_updated, new_items, affected_tab_ids = update_all_feeds()
                    logger.info(
                        "Scheduled update completed: %s feeds updated, %s new items",
                        feeds_updated,
                        new_items,
                    )
                    # Invalidate the cache after updates
                    if new_items > 0 and affected_tab_ids:
                        for tab_id in affected_tab_ids:
                            invalidate_tab_feeds_cache(
                                tab_id, invalidate_tabs=False)
                        invalidate_tabs_cache()
                        logger.info(
                            "Granular cache invalidation completed for affected tabs: %s",
                            affected_tab_ids,
                        )

                    # Announce the update to any listening clients
                    event_data = {
                        "feeds_processed": feeds_updated,
                        "new_items": new_items,
                        "affected_tab_ids": (
                            sorted(list(affected_tab_ids)
                                   ) if affected_tab_ids else []
                        ),
                    }
                    msg = f"data: {json.dumps(event_data)}\n\n"
                    announcer.announce(msg=msg)
                except Exception as e:
                    logger.error(
                        "Error during scheduled feed update: %s", e, exc_info=True
                    )
    except Exception:
        # Lock acquisition failed (another worker is running the job), just skip
        pass


@scheduler.scheduled_job(
    "interval", minutes=OPML_AUTOSAVE_INTERVAL_MINUTES, id="autosave_opml"
)
def scheduled_opml_autosave():
    """Scheduled job to periodically save OPML to disk."""
    with app.app_context():
        logger.info(
            "Running scheduled OPML autosave (every %d minutes)",
            OPML_AUTOSAVE_INTERVAL_MINUTES,
        )
        try:
            autosave_opml()
        except Exception:
            logger.exception("Error during scheduled OPML autosave")


if not app.config.get("TESTING"):
    # Ensure scheduler only runs once in debug mode (only in the child reloader process)
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        try:
            scheduler.start()
            atexit.register(scheduler.shutdown)
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown()

# --- Error Handlers ---


@app.errorhandler(404)
def not_found_error(_):
    """Handles 404 Not Found errors with a JSON response."""
    logger.warning("404 Not Found: %s", request.path)
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handles 500 Internal Server Errors with a JSON response and logs the error."""
    logger.error("500 Internal Server Error: %s", error, exc_info=True)
    # Rollback the session in case the error was database-related
    db.session.rollback()
    return jsonify({"error": "An internal server error occurred"}), 500


# --- Static and Stream Routes ---

FRONTEND_FOLDER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)


@app.route("/")
def serve_index():
    """Serves the main index.html file."""
    return send_from_directory(FRONTEND_FOLDER, "index.html")


@app.route("/<path:filename>")
def serve_static_files(filename):
    """Serves static files like CSS and JS from the frontend folder."""
    # Basic security check: prevent accessing files outside the frontend folder
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid path"}), 400
    return send_from_directory(FRONTEND_FOLDER, filename)


@app.route("/api/stream")
def stream():
    """Endpoint for Server-Sent Events (SSE) to stream updates."""
    return Response(announcer.listen(), mimetype="text/event-stream")


if __name__ == "__main__":
    # Start the Flask development server for local testing.
    is_debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    logger.info("Starting Flask app (Debug mode: %s)", is_debug_mode)
    app.run(host="127.0.0.1", port=5000, debug=is_debug_mode)  # nosec B104
    logger.info("SheepVibes application finished.")
