"""Blueprint for OPML import and export operations."""

import logging
import os
from ..utils.xml_utils import UnsafeElement, UnsafeSubElement, tostring


from filelock import FileLock, Timeout
from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from ..feed_service import import_opml as import_opml_service
from ..models import Tab

opml_bp = Blueprint("opml", __name__, url_prefix="/api/opml")
logger = logging.getLogger(__name__)


def _generate_opml_string(tabs=None):
    """Generates the OPML string from the database.

    Args:
        tabs (list): Optional list of Tab objects with eager loaded feeds.
                     If None, it will be queried.

    Returns:
        tuple[str, int, int]: A tuple containing the OPML string, tab count, and feed count.
    """
    # See security_xml.md for secure XML guidelines
    opml_element = UnsafeElement("opml", version="2.0")
    head_element = UnsafeSubElement(opml_element, "head")
    title_element = UnsafeSubElement(head_element, "title")
    title_element.text = "SheepVibes Feeds"
    body_element = UnsafeSubElement(opml_element, "body")

    if tabs is None:
        # Eager load feeds to avoid N+1 queries
        tabs = Tab.query.options(selectinload(Tab.feeds)).order_by(
            Tab.order).all()

    for tab in tabs:
        # Skip tabs with no feeds
        if not tab.feeds:
            continue

        # Create a folder outline for the tab
        folder_outline = UnsafeSubElement(body_element, "outline")
        folder_outline.set("text", tab.name)
        folder_outline.set("title", tab.name)
        # Sort feeds by name for deterministic output because relation order is not guaranteed
        sorted_feeds = sorted(tab.feeds, key=lambda f: f.name)

        # Add feeds for this tab
        for feed in sorted_feeds:
            feed_outline = UnsafeSubElement(folder_outline, "outline")
            feed_outline.set("text", feed.name)
            feed_outline.set("title", feed.name)
            feed_outline.set("xmlUrl", feed.url)
            feed_outline.set("type", "rss")
            if feed.site_link:
                feed_outline.set("htmlUrl", feed.site_link)

    # Convert the XML tree to a string
    opml_string = tostring(opml_element, encoding="utf-8",
                           method="xml").decode("utf-8")

    feed_count = sum(len(tab.feeds) for tab in tabs)
    tab_count = sum(1 for tab in tabs if tab.feeds)

    return opml_string, tab_count, feed_count


def _validate_opml_file_request():
    """Validates the uploaded OPML file from the request."""
    if "file" not in request.files:
        return None, (jsonify({"error": "No file part in the request"}), 400)
    opml_file = request.files["file"]
    if opml_file.filename == "":
        return None, (jsonify({"error": "No file selected for uploading"}), 400)
    if not opml_file:
        return None, (jsonify({"error": "File object is empty"}), 400)

    # Basic security: check file extension
    allowed_extensions = (".opml", ".xml", ".txt")
    _, ext = os.path.splitext(opml_file.filename)
    if ext.lower() not in allowed_extensions:
        err_msg = f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        return None, (jsonify({"error": err_msg}), 400)

    # Basic security: check file size (5MB limit)
    opml_file.seek(0, os.SEEK_END)
    size = opml_file.tell()
    opml_file.seek(0)
    if size > 5 * 1024 * 1024:
        return None, (jsonify({"error": "File is too large (max 5MB)"}), 400)

    return opml_file, None


@opml_bp.route("/import", methods=["POST"])
def import_opml():
    """Imports feeds from an OPML file, supporting nested structures as new tabs."""
    opml_file, error_resp = _validate_opml_file_request()
    if error_resp:
        return error_resp

    requested_tab_id_str = request.form.get("tab_id")

    # Call the service function
    result, error_info = import_opml_service(opml_file.stream,
                                             requested_tab_id_str)

    if error_info:
        error_json, status_code = error_info
        return jsonify(error_json), status_code

    return jsonify(result), 200


@opml_bp.route("/export", methods=["GET"])
def export_opml():
    """Exports all feeds as an OPML file.

    Returns:
        A Flask Response object containing the OPML file, or a JSON error response.
    """
    try:
        opml_string, tab_count, feed_count = _generate_opml_string()
    except SQLAlchemyError:
        logger.exception("Database error during OPML generation for export")
        return jsonify({"error": "Database error during OPML generation"}), 500
    except Exception:  # pylint: disable=broad-exception-caught
        # Catch unexpected errors during OPML generation
        logger.exception("Error during OPML generation for export")
        return jsonify({"error": "Failed to generate OPML export"}), 500

    response = Response(opml_string, mimetype="application/xml")
    response.headers["Content-Disposition"] = (
        'attachment; filename="sheepvibes_feeds.opml"')

    logger.info(
        "Successfully generated OPML export for %d feeds across %d tabs.",
        feed_count,
        tab_count,
    )
    return response


def _get_autosave_directory():
    """Determines the autosave directory with flexible configuration.

    Priority:
    1. DATA_DIR config/environment variable (explicit configuration)
    2. Directory of the SQLite database file (alongside user data)
    3. PROJECT_ROOT/data (default fallback)
    """
    # 1. Check for explicit DATA_DIR configuration
    data_dir = current_app.config.get("DATA_DIR") or os.environ.get("DATA_DIR")

    if not data_dir:
        # 2. Try to use the directory of the SQLite database
        db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if db_uri.startswith("sqlite:///"):
            db_path = db_uri.replace("sqlite:///", "")
            if db_path == ":memory:":
                logger.warning(
                    "Skipping OPML autosave because database is in-memory.")
                return None
            # Resolve relative paths to absolute ones to find the data directory correctly
            try:
                abs_db_path = os.path.abspath(db_path)
                data_dir = os.path.dirname(abs_db_path)
                logger.debug(
                    "Resolved autosave directory from SQLite path: %s",
                    data_dir)
            except Exception:
                logger.warning(
                    "Could not resolve absolute path for SQLite DB: %s",
                    db_path)

    if not data_dir:
        # 3. Fall back to PROJECT_ROOT/data
        project_root = current_app.config.get("PROJECT_ROOT", "")
        if project_root:
            data_dir = os.path.join(project_root, "data")

    if not data_dir:
        logger.warning(
            "Could not determine autosave directory. Skipping OPML autosave.")
        return None

    try:
        os.makedirs(data_dir, exist_ok=True)
    except OSError:
        logger.exception(
            "Could not create or access autosave directory %s. Skipping OPML autosave.",
            data_dir,
        )
        return None

    return data_dir


def _write_atomically_with_lock(autosave_path, opml_string):
    """Writes content to a file atomically using a lock and temp file."""
    temp_path = f"{autosave_path}.tmp"
    lock_path = f"{autosave_path}.lock"
    lock = FileLock(lock_path, timeout=5)

    try:
        # Use a file lock to prevent race conditions in multi-process environments
        with lock:
            # Use atomic write: write to a temporary file then rename
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(opml_string)
            os.replace(temp_path, autosave_path)
            return True
    except Timeout:
        logger.warning(
            "Could not acquire lock for %s, another process is likely writing the backup.",
            autosave_path,
        )
    except OSError:
        logger.exception("Failed to write autosave file to %s", autosave_path)
        # Cleanup temp file if it exists
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError as e:
                logger.warning("Failed to remove temporary file %s: %s",
                               temp_path, e)
    return False


def autosave_opml():
    """Saves the current feeds as an OPML file to the data directory."""
    opml_string, tab_count, feed_count = _generate_opml_string()

    data_dir = _get_autosave_directory()
    if not data_dir:
        return

    autosave_path = os.path.join(data_dir, "sheepvibes_backup.opml")

    if _write_atomically_with_lock(autosave_path, opml_string):
        logger.info(
            "OPML autosaved to %s (%d feeds in %d tabs)",
            autosave_path,
            feed_count,
            tab_count,
        )
