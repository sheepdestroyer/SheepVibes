import logging
import os
import xml.etree.ElementTree as ET  # nosec B405

from filelock import FileLock, Timeout
from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy.orm import selectinload

from ..constants import DEFAULT_OPML_IMPORT_TAB_NAME
from ..extensions import db
from ..feed_service import import_opml as import_opml_service
from ..models import Feed, Tab

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
    opml_element = ET.Element("opml", version="2.0")
    head_element = ET.SubElement(opml_element, "head")
    title_element = ET.SubElement(head_element, "title")
    title_element.text = "SheepVibes Feeds"
    body_element = ET.SubElement(opml_element, "body")

    if tabs is None:
        # Eager load feeds to avoid N+1 queries
        tabs = Tab.query.options(selectinload(Tab.feeds)).order_by(
            Tab.order).all()

    for tab in tabs:
        # Skip tabs with no feeds
        if not tab.feeds:
            continue

        # Create a folder outline for the tab
        folder_outline = ET.SubElement(body_element, "outline")
        folder_outline.set("text", tab.name)
        folder_outline.set("title", tab.name)
        # Sort feeds by name for deterministic output because relation order is not guaranteed
        sorted_feeds = sorted(tab.feeds, key=lambda f: f.name)

        # Add feeds for this tab
        for feed in sorted_feeds:
            feed_outline = ET.SubElement(folder_outline, "outline")
            feed_outline.set("text", feed.name)
            feed_outline.set("title", feed.name)
            feed_outline.set("xmlUrl", feed.url)
            feed_outline.set("type", "rss")
            if feed.site_link:
                feed_outline.set("htmlUrl", feed.site_link)

    # Convert the XML tree to a string
    opml_string = ET.tostring(opml_element, encoding="utf-8",
                              method="xml").decode("utf-8")

    feed_count = sum(len(tab.feeds) for tab in tabs)
    tab_count = sum(1 for tab in tabs if tab.feeds)

    return opml_string, tab_count, feed_count


def _process_opml_outlines_recursive(
    outline_elements,
    current_tab_id,
    current_tab_name,  # For logging/context, not strictly for db ops here
    all_existing_feed_urls_set,
    newly_added_feeds_list,
    imported_count_wrapper,  # Use list/dict for mutable integer
    skipped_count_wrapper,  # Use list/dict for mutable integer
    affected_tab_ids_set,
):
    """Recursively processes OPML outline elements.

    Feeds are added to `newly_added_feeds_list` but not committed here.
    New tabs (folders) are committed immediately to get their IDs.
    """
    for outline_element in outline_elements:
        folder_type_attr = outline_element.get(
            "type")  # For Netvibes type skipping
        # Netvibes uses 'title', some others use 'text'. Prioritize 'title'.
        title_attr = outline_element.get("title")
        text_attr = outline_element.get("text")
        element_name = (
            title_attr.strip() if title_attr and title_attr.strip() else
            (text_attr.strip() if text_attr and text_attr.strip() else ""))

        xml_url = outline_element.get("xmlUrl")
        child_outlines = list(
            outline_element)  # More robust than findall for direct children

        if xml_url:  # It's a feed
            feed_name = (element_name if element_name else xml_url
                         )  # Fallback to URL if no title/text

            if xml_url in all_existing_feed_urls_set:
                logger.info(
                    "OPML import: Feed with URL '%s' already exists. Skipping.",
                    xml_url)
                skipped_count_wrapper[0] += 1
                continue

            try:
                new_feed = Feed(tab_id=current_tab_id,
                                name=feed_name,
                                url=xml_url)
                # Add to session, but commit will be done in batch later for feeds
                db.session.add(new_feed)
                newly_added_feeds_list.append(new_feed)
                all_existing_feed_urls_set.add(
                    xml_url)  # Track for current import session
                imported_count_wrapper[0] += 1
                affected_tab_ids_set.add(current_tab_id)
                logger.info(
                    "OPML import: Prepared new feed '%s' (%s) for tab ID %s ('%s').",
                    feed_name,
                    xml_url,
                    current_tab_id,
                    current_tab_name,
                )
            except Exception:
                # Should be rare if checks are done, but good for safety
                logger.exception("OPML import: Error preparing feed '%s'",
                                 feed_name)
                skipped_count_wrapper[0] += 1

        elif (not xml_url and element_name and folder_type_attr
              and folder_type_attr in SKIPPED_FOLDER_TYPES):
            logger.info(
                "OPML import: Skipping Netvibes-specific folder '%s' due to type: %s.",
                element_name,
                folder_type_attr,
            )
            continue

        elif (not xml_url and element_name and child_outlines
              ):  # It's a folder (has a name, no xmlUrl, AND children)
            folder_name = element_name
            existing_tab = Tab.query.filter_by(name=folder_name).first()

            nested_tab_id = None
            nested_tab_name = None

            if existing_tab:
                nested_tab_id = existing_tab.id
                nested_tab_name = existing_tab.name
                logger.info(
                    "OPML import: Folder '%s' matches existing tab '%s' (ID: %s). Feeds will be added to it.",
                    folder_name,
                    nested_tab_name,
                    nested_tab_id,
                )
            else:
                max_order = db.session.query(db.func.max(Tab.order)).scalar()
                new_order = (max_order or -1) + 1
                new_folder_tab = Tab(name=folder_name, order=new_order)
                db.session.add(new_folder_tab)
                try:
                    db.session.flush(
                    )  # Flush to assign an ID without committing the transaction
                    logger.info(
                        "OPML import: Created new tab '%s' (ID: %s) from OPML folder.",
                        new_folder_tab.name,
                        new_folder_tab.id,
                    )
                    invalidate_tabs_cache()  # Crucial: new tab added
                    nested_tab_id = new_folder_tab.id
                    nested_tab_name = new_folder_tab.name
                except Exception:
                    db.session.rollback()
                    logger.exception(
                        "OPML import: Failed to commit new tab '%s'. Skipping this folder and its contents.",
                        folder_name,
                    )
                    skipped_count_wrapper[0] += len(
                        child_outlines)  # Approximate skip count
                    continue  # Skip this folder

            if nested_tab_id and nested_tab_name:
                _process_opml_outlines_recursive(
                    child_outlines,
                    nested_tab_id,
                    nested_tab_name,
                    all_existing_feed_urls_set,
                    newly_added_feeds_list,
                    imported_count_wrapper,
                    skipped_count_wrapper,
                    affected_tab_ids_set,
                )
        elif not xml_url and not element_name and child_outlines:
            # Folder without a title, process its children in the current tab
            logger.info(
                "OPML import: Processing children of an untitled folder under current tab '%s'.",
                current_tab_name,
            )
            _process_opml_outlines_recursive(
                child_outlines,
                current_tab_id,  # Use current tab_id
                current_tab_name,
                all_existing_feed_urls_set,
                newly_added_feeds_list,
                imported_count_wrapper,
                skipped_count_wrapper,
                affected_tab_ids_set,
            )
        else:
            logger.info(
                "OPML import: Skipping outline (Name: '%s', xmlUrl: %s, Children: %s) as it's not a feed or folder.",
                element_name,
                xml_url,
                len(child_outlines),
            )
            if not xml_url:
                skipped_count_wrapper[0] += 1


def _determine_target_tab(requested_tab_id_str):
    """
    Determines the target tab for OPML import.
    Returns:
        tuple: (tab_id, tab_name, was_created)
        - tab_id (int): The ID of the target tab.
        - tab_name (str): The name of the target tab.
        - was_created (bool): True if a new default tab was created, False otherwise.
        - error_response (tuple): (json_response, status_code) if an error occurred, else None.
    """
    target_tab_id = None
    target_tab_name = None
    was_created = False

    if requested_tab_id_str:
        try:
            tab_id_val = int(requested_tab_id_str)
            tab_obj = db.session.get(Tab, tab_id_val)
            if tab_obj:
                target_tab_id = tab_obj.id
                target_tab_name = tab_obj.name
            else:
                logger.warning(
                    "OPML import: Requested tab_id %s not found. Will use default logic.",
                    tab_id_val,
                )
        except ValueError:
            logger.warning(
                "OPML import: Invalid tab_id format '%s'. Will use default logic.",
                requested_tab_id_str,
            )

    if not target_tab_id:
        default_tab_obj = Tab.query.order_by(Tab.order).first()
        if default_tab_obj:
            target_tab_id = default_tab_obj.id
            target_tab_name = default_tab_obj.name
        else:
            logger.info(
                "OPML import: No tabs exist. Creating a default tab for top-level feeds."
            )
            default_tab_name_for_creation = DEFAULT_OPML_IMPORT_TAB_NAME
            temp_tab_check = Tab.query.filter_by(
                name=default_tab_name_for_creation).first()
            if temp_tab_check:
                target_tab_id = temp_tab_check.id
                target_tab_name = temp_tab_check.name
            else:
                newly_created_default_tab = Tab(
                    name=default_tab_name_for_creation, order=0)
                db.session.add(newly_created_default_tab)
                try:
                    db.session.commit()
                    logger.info(
                        "OPML import: Created default tab '%s' (ID: %s).",
                        newly_created_default_tab.name,
                        newly_created_default_tab.id,
                    )
                    invalidate_tabs_cache()
                    target_tab_id = newly_created_default_tab.id
                    target_tab_name = newly_created_default_tab.name
                    was_created = True
                except Exception as e_tab_commit:
                    db.session.rollback()
                    logger.error(
                        "OPML import: Failed to create default tab '%s': %s",
                        default_tab_name_for_creation,
                        e_tab_commit,
                        exc_info=True,
                    )
                    return (
                        None,
                        None,
                        False,
                        (
                            jsonify({
                                "error":
                                "Failed to create a default tab for import."
                            }),
                            500,
                        ),
                    )

    if not target_tab_id:
        logger.error(
            "OPML import: Critical error - failed to determine a top-level target tab."
        )
        return (
            None,
            None,
            False,
            (jsonify({"error":
                      "Failed to determine a target tab for import."}), 500),
        )

    return target_tab_id, target_tab_name, was_created, None


def _cleanup_empty_default_tab(was_created, tab_id, tab_name,
                               affected_tab_ids):
    """Cleans up the default tab if it was created for this import but remains empty."""
    if was_created and tab_id not in affected_tab_ids:
        try:
            tab_to_del = db.session.get(Tab, tab_id)
            if tab_to_del and not tab_to_del.feeds:
                db.session.delete(tab_to_del)
                db.session.commit()
                invalidate_tabs_cache()
                logger.info(
                    "OPML import: Removed empty default tab '%s' (ID: %s) created during import.",
                    tab_name,
                    tab_id,
                )
        except Exception as e_cleanup:
            db.session.rollback()
            logger.warning(
                "OPML import: Failed to cleanup empty default tab '%s': %s",
                tab_name,
                e_cleanup,
            )


def _validate_opml_file_request():
    """Validates the uploaded OPML file from the request."""
    if "file" not in request.files:
        return None, (jsonify({"error": "No file part in the request"}), 400)
    opml_file = request.files["file"]
    if opml_file.filename == "":
        return None, (jsonify({"error":
                               "No file selected for uploading"}), 400)
    if not opml_file:
        return None, (jsonify({"error": "File object is empty"}), 400)

    # Basic security: check file extension
    allowed_extensions = {".opml", ".xml", ".txt"}
    _, ext = os.path.splitext(opml_file.filename)
    if ext.lower() not in allowed_extensions:
        return None, (
            jsonify({
                "error":
                f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
            }),
            400,
        )

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
    except Exception:
        # Catch unexpected errors during OPML generation
        logger.exception("Error during OPML generation for export")
        return jsonify({"error": "Failed to generate OPML export"}), 500

    else:
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
