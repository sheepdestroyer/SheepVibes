import logging
import os
import xml.etree.ElementTree as ET

from filelock import FileLock, Timeout
from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy import func
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import selectinload

from ..cache_utils import (
    invalidate_tab_feeds_cache,
    invalidate_tabs_cache,
    make_tabs_cache_key,
)
from ..extensions import cache, db
from ..feed_service import fetch_and_update_feed
from ..models import Feed, Tab

opml_bp = Blueprint("opml", __name__, url_prefix="/api/opml")
logger = logging.getLogger(__name__)

# --- OPML Import Configuration ---
SKIPPED_FOLDER_TYPES = {
    "UWA",
    "Webnote",
    "LinkModule",
}  # Netvibes specific types to ignore for tab creation


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
        tabs = Tab.query.options(selectinload(
            Tab.feeds)).order_by(Tab.order).all()

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
    opml_string = ET.tostring(opml_element, encoding="utf-8", method="xml").decode(
        "utf-8"
    )

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
            title_attr.strip()
            if title_attr and title_attr.strip()
            else (text_attr.strip() if text_attr and text_attr.strip() else "")
        )

        xml_url = outline_element.get("xmlUrl")
        child_outlines = list(
            outline_element
        )  # More robust than findall for direct children

        if xml_url:  # It's a feed
            feed_name = (
                element_name if element_name else xml_url
            )  # Fallback to URL if no title/text

            if xml_url in all_existing_feed_urls_set:
                logger.info(
                    "OPML import: Feed with URL '%s' already exists. Skipping.", xml_url
                )
                skipped_count_wrapper[0] += 1
                continue

            try:
                new_feed = Feed(tab_id=current_tab_id,
                                name=feed_name, url=xml_url)
                # Add to session, but commit will be done in batch later for feeds
                db.session.add(new_feed)
                newly_added_feeds_list.append(new_feed)
                all_existing_feed_urls_set.add(
                    xml_url
                )  # Track for current import session
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
                logger.exception(
                    "OPML import: Error preparing feed '%s'", feed_name)
                skipped_count_wrapper[0] += 1

        elif (
            not xml_url
            and element_name
            and folder_type_attr
            and folder_type_attr in SKIPPED_FOLDER_TYPES
        ):
            logger.info(
                "OPML import: Skipping Netvibes-specific folder '%s' due to type: %s.",
                element_name,
                folder_type_attr,
            )
            continue

        elif (
            not xml_url and element_name and child_outlines
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
                    db.session.commit()  # Commit new tab immediately to get its ID
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
                        child_outlines
                    )  # Approximate skip count
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
                "OPML import: Skipping outline element (Name: '%s', xmlUrl: %s, Children: %s) as it's not a feed or a non-empty folder.",
                element_name,
                xml_url,
                len(child_outlines),
            )
            if not xml_url:
                skipped_count_wrapper[0] += 1


@opml_bp.route("/import", methods=["POST"])
def import_opml():
    """Imports feeds from an OPML file, supporting nested structures as new tabs."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    opml_file = request.files["file"]
    if opml_file.filename == "":
        return jsonify({"error": "No file selected for uploading"}), 400
    if not opml_file:
        return jsonify({"error": "File object is empty"}), 400

    imported_count_wrapper = [0]
    skipped_count_wrapper = [0]
    affected_tab_ids_set = set()
    newly_added_feeds_list = []
    was_default_tab_created_for_this_import = False

    try:
        tree = ET.parse(opml_file.stream)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(
            f"OPML import failed: Malformed XML. Error: {e}", exc_info=True)
        return jsonify({"error": f"Malformed OPML file: {e}"}), 400
    except Exception as e:
        logger.error(
            f"OPML import failed: Could not parse file stream. Error: {e}",
            exc_info=True,
        )
        return jsonify({"error": f"OPML import failed: {e}"}), 500

    top_level_target_tab_id = None
    top_level_target_tab_name = None
    requested_tab_id_str = request.form.get("tab_id")

    if requested_tab_id_str:
        try:
            tab_id_val = int(requested_tab_id_str)
            tab_obj = db.session.get(Tab, tab_id_val)
            if tab_obj:
                top_level_target_tab_id = tab_obj.id
                top_level_target_tab_name = tab_obj.name
            else:
                logger.warning(
                    f"OPML import: Requested tab_id {tab_id_val} not found. Will use default logic."
                )
        except ValueError:
            logger.warning(
                f"OPML import: Invalid tab_id format '{requested_tab_id_str}'. Will use default logic."
            )

    if not top_level_target_tab_id:
        default_tab_obj = Tab.query.order_by(Tab.order).first()
        if default_tab_obj:
            top_level_target_tab_id = default_tab_obj.id
            top_level_target_tab_name = default_tab_obj.name
        else:
            logger.info(
                "OPML import: No tabs exist. Creating a default tab for top-level feeds."
            )
            default_tab_name_for_creation = "Imported Feeds"
            temp_tab_check = Tab.query.filter_by(
                name=default_tab_name_for_creation
            ).first()
            if temp_tab_check:
                top_level_target_tab_id = temp_tab_check.id
                top_level_target_tab_name = temp_tab_check.name
            else:
                newly_created_default_tab = Tab(
                    name=default_tab_name_for_creation, order=0
                )
                db.session.add(newly_created_default_tab)
                try:
                    db.session.commit()
                    logger.info(
                        f"OPML import: Created new default tab '{newly_created_default_tab.name}' (ID: {newly_created_default_tab.id})."
                    )
                    invalidate_tabs_cache()
                    top_level_target_tab_id = newly_created_default_tab.id
                    top_level_target_tab_name = newly_created_default_tab.name
                    was_default_tab_created_for_this_import = True
                except Exception as e_tab_commit:
                    db.session.rollback()
                    logger.error(
                        f"OPML import: Failed to create default tab '{default_tab_name_for_creation}': {e_tab_commit}",
                        exc_info=True,
                    )
                    return (
                        jsonify(
                            {"error": "Failed to create a default tab for import."}
                        ),
                        500,
                    )

    if not top_level_target_tab_id:
        logger.error(
            "OPML import: Critical error - failed to determine a top-level target tab."
        )
        return jsonify({"error": "Failed to determine a target tab for import."}), 500

    all_existing_feed_urls_set = {feed.url for feed in Feed.query.all()}

    opml_body = root.find("body")
    if opml_body is None:
        logger.warning("OPML import: No <body> element found in OPML file.")
        return (
            jsonify(
                {
                    "message": "No feeds found in OPML (missing body).",
                    "imported_count": 0,
                    "skipped_count": 0,
                    "tab_id": top_level_target_tab_id,
                    "tab_name": top_level_target_tab_name,
                }
            ),
            200,
        )

    _process_opml_outlines_recursive(
        opml_body.findall("outline"),
        top_level_target_tab_id,
        top_level_target_tab_name,
        all_existing_feed_urls_set,
        newly_added_feeds_list,
        imported_count_wrapper,
        skipped_count_wrapper,
        affected_tab_ids_set,
    )

    imported_final_count = imported_count_wrapper[0]
    skipped_final_count = skipped_count_wrapper[0]

    if newly_added_feeds_list:
        try:
            db.session.commit()
            logger.info(
                f"OPML import: Successfully batch-committed {len(newly_added_feeds_list)} new feeds to the database."
            )

            logger.info(
                f"OPML import: Attempting to fetch initial items for {len(newly_added_feeds_list)} newly added feeds."
            )
            for feed_obj in newly_added_feeds_list:
                if feed_obj.id:
                    try:
                        fetch_and_update_feed(feed_obj.id)
                    except Exception as fetch_e:
                        logger.error(
                            f"OPML import: Error fetching items for new feed {feed_obj.name} (ID: {feed_obj.id}): {fetch_e}",
                            exc_info=True,
                        )
                else:
                    logger.error(
                        f"OPML import: Feed '{feed_obj.name}' missing ID after batch commit, cannot fetch items."
                    )
            logger.info(
                f"OPML import: Finished attempting to fetch initial items for new feeds."
            )
        except Exception as e_commit_feeds:
            db.session.rollback()
            logger.error(
                f"OPML import: Database commit failed for new feeds: {e_commit_feeds}",
                exc_info=True,
            )
            return (
                jsonify({"error": "Database error during final feed import step."}),
                500,
            )

    if affected_tab_ids_set:
        invalidate_tabs_cache()
        for tab_id_to_invalidate in affected_tab_ids_set:
            invalidate_tab_feeds_cache(tab_id_to_invalidate)
        logger.info(
            f"OPML import: Feed-related caches invalidated for tabs: {affected_tab_ids_set}."
        )

    if not opml_body.findall("outline") and not newly_added_feeds_list:
        logger.info(
            "OPML import: No <outline> elements found in the OPML body to process as feeds or folders."
        )
        return (
            jsonify(
                {
                    "message": "No feed entries or folders found in the OPML file.",
                    "imported_count": 0,
                    "skipped_count": skipped_final_count,
                    "tab_id": top_level_target_tab_id,
                    "tab_name": top_level_target_tab_name,
                }
            ),
            200,
        )

    if (
        was_default_tab_created_for_this_import
        and top_level_target_tab_name == "Imported Feeds"
        and top_level_target_tab_id not in affected_tab_ids_set
    ):
        feeds_in_default_tab = Feed.query.filter_by(
            tab_id=top_level_target_tab_id
        ).count()
        if feeds_in_default_tab == 0:
            logger.info(
                f"OPML import: The default 'Imported Feeds' tab (ID: {top_level_target_tab_id}) created during this import is empty. Deleting it."
            )
            try:
                tab_to_delete = db.session.get(Tab, top_level_target_tab_id)
                if tab_to_delete:
                    db.session.delete(tab_to_delete)
                    db.session.commit()
                    invalidate_tabs_cache()
                    logger.info(
                        f"OPML import: Successfully deleted empty 'Imported Feeds' tab (ID: {top_level_target_tab_id})."
                    )
                else:
                    logger.warning(
                        f"OPML import: Tried to delete empty 'Imported Feeds' tab (ID: {top_level_target_tab_id}), but it was not found in session."
                    )
            except Exception as e_del_tab:
                db.session.rollback()
                logger.error(
                    f"OPML import: Failed to delete empty 'Imported Feeds' tab (ID: {top_level_target_tab_id}): {e_del_tab}",
                    exc_info=True,
                )
        else:
            logger.info(
                f"OPML import: The default 'Imported Feeds' tab (ID: {top_level_target_tab_id}) was created but contains {feeds_in_default_tab} feeds. It will not be deleted."
            )

    return (
        jsonify(
            {
                "message": f'{imported_final_count} feeds imported. {skipped_final_count} feeds skipped. Feeds were imported into relevant tabs or default tab "{top_level_target_tab_name}".',
                "imported_count": imported_final_count,
                "skipped_count": skipped_final_count,
                "tab_id": top_level_target_tab_id,
                "tab_name": top_level_target_tab_name,
            }
        ),
        200,
    )


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
            'attachment; filename="sheepvibes_feeds.opml"'
        )

        logger.info(
            "Successfully generated OPML export for %d feeds across %d tabs.",
            feed_count,
            tab_count,
        )
        return response


def _get_autosave_directory():
    """Determines the autosave directory based on the database URI."""
    # Use current_app to access config
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")

    # Default to an absolute 'data' path in the project root to avoid CWD issues
    # Default to an absolute 'data' path using the configured PROJECT_ROOT
    project_root = current_app.config["PROJECT_ROOT"]
    data_dir = os.path.join(project_root, "data")

    try:
        url = make_url(db_uri)
        if url.drivername == "sqlite":
            # Check for in-memory database variations like 'sqlite://' or 'sqlite:///:memory:'
            if not url.database or url.database == ":memory:":
                logger.warning(
                    "Skipping OPML autosave because database is in-memory.")
                return None
            # For file-based sqlite, use its directory, resolving relative paths against the project root.
            # However, if it's absolute, use it directly.
            # Note: url.database string might be relative.
            if os.path.isabs(url.database):
                db_path = url.database
            else:
                # If relative, it's relative to where app was run? Or config setup?
                # In app.py logic, it resolved relative to project root.
                # Just trusting url.database as resolved by make_url might tricky if it's relative.
                # But generally if app.config used absolute path, make_url reflects it.
                # If app.config used "sqlite:///sheepvibes.db", url.database is "sheepvibes.db".
                # We prefer the standard data dir if we can't be sure, but let's try to match logic.
                db_path = os.path.join(project_root, url.database)

            data_dir = os.path.dirname(db_path)
        # For non-sqlite databases, the default data_dir (project_root/data) is used.
    except (ArgumentError, ValueError):
        # We catch specific parsing errors here. make_url can raise ArgumentError.
        logger.exception(
            "Error parsing database URI for autosave path. Using default: %s", data_dir
        )

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
                logger.warning(
                    "Failed to remove temporary file %s: %s", temp_path, e)
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
