"""Service module for fetching, parsing, and processing RSS/Atom feeds."""

# Import necessary libraries
# Use dateutil for robust date parsing
import concurrent.futures
import datetime  # Import the full module
import hashlib
import http.client
import ipaddress
import json
import logging  # Standard logging
import os
import socket
import ssl
import urllib.request
from dataclasses import dataclass
from datetime import timezone  # Specifically import timezone
from urllib.parse import urljoin, urlparse
from xml.etree.ElementTree import Element
from xml.sax import SAXParseException
from xml.sax.handler import ContentHandler

import defusedxml.ElementTree as SafeET
import defusedxml.sax
import feedparser
import sqlalchemy.exc
from dateutil import parser as date_parser
from defusedxml.common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)
from sqlalchemy.exc import IntegrityError

from .cache_utils import (
    invalidate_tab_feeds_cache,
    invalidate_tabs_cache,
)
from .constants import (
    DEFAULT_OPML_IMPORT_TAB_NAME,
    DELETE_CHUNK_SIZE,
    MAX_ITEMS_PER_FEED,
    SKIPPED_FOLDER_TYPES,
)

# Import database models from the new models.py
from .models import Feed, FeedItem, Tab, db
from .sse import announcer

# Set up logger for this module
logger = logging.getLogger(__name__)

# Type alias for the stack items: (list of XML elements, current_tab_id, current_tab_name)
OpmlStackItem = tuple[list[Element], int, str]


@dataclass
class OpmlImportState:
    """Holds the shared state for OPML processing."""

    stack: list[OpmlStackItem]
    all_existing_feed_urls_set: set[str]
    newly_added_feeds_list: list[Feed]
    affected_tab_ids_set: set[int]
    imported_count: int = 0
    skipped_count: int = 0


def _count_feeds_in_opml(root):
    """Recursively counts the number of feed outlines in the OPML."""
    return len(root.findall(".//outline[@xmlUrl]"))


# --- OPML Import Configuration ---
OPML_IMPORT_PROCESSING_WEIGHT = 50  # Percent of total progress
OPML_IMPORT_FETCHING_WEIGHT = 50  # Percent of total progress


def _sanitize_for_log(text):
    """Sanitizes text for logging to prevent log injection."""
    if not text:
        return ""
    # Escape newlines/carriage returns, then remove non-printable characters
    text = str(text).replace("\n", "\\n").replace("\r", "\\r")
    return "".join(ch for ch in text if ch.isprintable())[:200]


def validate_link_structure(url, schemes=("http", "https")):
    """
    Validates a URL structure for legitimate schemes and network location.
    Returns the cleaned URL if valid, or None if invalid.
    """
    if not url:
        return None
    cleaned = url.strip()
    try:
        parsed = urlparse(cleaned)
        if parsed.scheme.lower() in schemes and parsed.netloc:
            return cleaned
        return None
    except Exception:
        return None


def is_valid_feed_url(url):
    """Checks if a URL is a valid feed URL (http/https only)."""
    return bool(validate_link_structure(url))


def _calculate_and_announce_progress(processed_count, total_count,
                                     last_announced_percent):
    """Calculates progress and announces it if significant change occurred."""
    if total_count > 0:
        # Cap progress value, as processed_count can exceed total_count.
        progress_val = min(
            OPML_IMPORT_PROCESSING_WEIGHT,
            (processed_count * OPML_IMPORT_PROCESSING_WEIGHT) // total_count,
        )
    else:
        progress_val = OPML_IMPORT_PROCESSING_WEIGHT

    current_percent = progress_val
    should_announce = (processed_count == 0 or processed_count >= total_count
                       or (current_percent != last_announced_percent
                           and current_percent % 5 == 0)
                       or processed_count % 20 == 0)

    if should_announce:
        status_msg = f"Processing OPML... ({processed_count} outlines analyzed)"
        event_data = {
            "type": "progress",
            "status": status_msg,
            "value": progress_val,
            "max": 100,
        }
        announcer.announce(msg=f"data: {json.dumps(event_data)}\n\n")
        return current_percent
    return last_announced_percent


def _process_opml_feed_node(
    xml_url,
    feed_name,
    current_tab_id,
    state: OpmlImportState,
):
    """Processes a single feed node from the OPML."""
    # XSS Prevention: Validate URL scheme
    if not is_valid_feed_url(xml_url):
        logger.warning(
            "OPML import: Skipping feed '%s' with invalid URL scheme: %s",
            _sanitize_for_log(feed_name),
            _sanitize_for_log(xml_url),
        )
        state.skipped_count += 1
        return

    if xml_url in state.all_existing_feed_urls_set:
        logger.info(
            "OPML import: Feed with URL '%s' already exists. Skipping.",
            _sanitize_for_log(xml_url),
        )
        state.skipped_count += 1
        return

    try:
        new_feed = Feed(tab_id=current_tab_id, name=feed_name, url=xml_url)
        db.session.add(new_feed)
        state.newly_added_feeds_list.append(new_feed)
        state.all_existing_feed_urls_set.add(xml_url)
        state.imported_count += 1
        state.affected_tab_ids_set.add(current_tab_id)
    except sqlalchemy.exc.SQLAlchemyError:
        logger.exception(
            "OPML import: Error preparing feed '%s'",
            _sanitize_for_log(feed_name),
        )
        state.skipped_count += 1


def _get_or_create_nested_tab(folder_name):
    """Finds an existing tab by name or creates a new one."""
    existing_tab = Tab.query.filter_by(name=folder_name).first()

    if existing_tab:
        return existing_tab.id, existing_tab.name

    max_order = db.session.query(db.func.max(Tab.order)).scalar()
    new_order = (max_order or -1) + 1
    new_folder_tab = Tab(name=folder_name, order=new_order)
    db.session.add(new_folder_tab)

    # Use a savepoint to prevent rolling back the entire session (and losing feeds)
    nested = db.session.begin_nested()
    try:
        db.session.flush()  # Flush to get the ID
        nested.commit()  # Commit savepoint
        invalidate_tabs_cache()
    except sqlalchemy.exc.IntegrityError:
        nested.rollback()  # Rollback only to savepoint
        # Remove the failed object from session identity map to prevent re-flush issues
        db.session.expunge(new_folder_tab)

        # Another process created this tab; fetch it
        existing_tab = Tab.query.filter_by(name=folder_name).first()
        if existing_tab:
            return existing_tab.id, existing_tab.name
        raise  # Re-raise if still not found
    return new_folder_tab.id, new_folder_tab.name


def _process_folder_node(
    element_name,
    folder_type_attr,
    child_outlines,
    current_tab_id,
    current_tab_name,
    state: OpmlImportState,
):
    """Processes a folder node (non-feed outline) from the OPML."""
    if folder_type_attr and folder_type_attr in SKIPPED_FOLDER_TYPES:
        logger.info(
            "OPML import: Skipping folder '%s' and its children (type: %s).",
            _sanitize_for_log(element_name),
            _sanitize_for_log(folder_type_attr),
        )
        return

    if element_name and child_outlines:
        try:
            nested_tab_id, nested_tab_name = _get_or_create_nested_tab(
                element_name)
            state.stack.append((list(reversed(child_outlines)), nested_tab_id,
                                nested_tab_name))
        except sqlalchemy.exc.SQLAlchemyError:
            logger.exception(
                "OPML import: DB error creating tab for folder '%s'. Skipping folder.",
                _sanitize_for_log(element_name),
            )
        return

    if not element_name and child_outlines:
        state.stack.append(
            (list(reversed(child_outlines)), current_tab_id, current_tab_name))
        return

    state.skipped_count += 1


def _process_single_outline_node(
    outline_element,
    current_tab_id,
    current_tab_name,
    state: OpmlImportState,
):
    """Processes a single OPML outline node, creating feeds or pushing folders to stack."""
    xml_url = outline_element.get("xmlUrl")
    title = (outline_element.get("title") or "").strip()
    text = (outline_element.get("text") or "").strip()
    element_name = title or text

    if xml_url:
        feed_name = element_name if element_name else xml_url
        _process_opml_feed_node(xml_url, feed_name, current_tab_id, state)
    else:
        _process_folder_node(
            element_name,
            outline_element.get("type"),
            list(outline_element),
            current_tab_id,
            current_tab_name,
            state,
        )


def _process_opml_outlines_iterative(
    initial_outline_elements,
    top_level_tab_id,
    top_level_tab_name,
    all_existing_feed_urls_set,
    total_outlines,
):
    """Iteratively processes OPML outline elements with weighted progress updates."""
    # Phase 1: Processing (0-50%)
    stack = [(
        list(reversed(initial_outline_elements)),
        top_level_tab_id,
        top_level_tab_name,
    )]
    state = OpmlImportState(
        stack=stack,
        all_existing_feed_urls_set=all_existing_feed_urls_set,
        newly_added_feeds_list=[],
        affected_tab_ids_set=set(),
    )
    last_announced_percent = -1

    processed_outline_count = 0
    while state.stack:
        outline_elements, current_tab_id, current_tab_name = state.stack.pop()

        while outline_elements:
            outline_element = outline_elements.pop()
            processed_outline_count += 1

            last_announced_percent = _calculate_and_announce_progress(
                processed_outline_count, total_outlines,
                last_announced_percent)

            _process_single_outline_node(
                outline_element,
                current_tab_id,
                current_tab_name,
                state,
            )
    return state


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
                _sanitize_for_log(requested_tab_id_str),
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
                    # Since this is the start of the import, we can safely commit the new tab
                    # without worrying about partial feed state (none exists yet).
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
                except sqlalchemy.exc.IntegrityError:
                    db.session.rollback()
                    # No need to expunge here as rollback clears the session
                    logger.info(
                        "OPML import: Race condition on default tab creation. Re-fetching tab '%s'.",
                        default_tab_name_for_creation,
                    )
                    # Another process likely created it. Fetch it.
                    refetched_tab = Tab.query.filter_by(
                        name=default_tab_name_for_creation).first()
                    if refetched_tab:
                        target_tab_id = refetched_tab.id
                        target_tab_name = refetched_tab.name
                        # was_created remains False, as this process didn't create it.
                    else:
                        # This is an unexpected state, but we should fail gracefully.
                        logger.error(
                            "OPML import: Failed to create or find default tab '%s' after race.",
                            default_tab_name_for_creation,
                        )
                        return (
                            None,
                            None,
                            False,
                            (
                                {
                                    "error":
                                    "Failed to create a default tab for import."
                                },
                                500,
                            ),
                        )
                except sqlalchemy.exc.SQLAlchemyError:
                    db.session.rollback()
                    logger.exception(
                        "OPML import: Failed to create default tab '%s'",
                        default_tab_name_for_creation,
                    )
                    return (
                        None,
                        None,
                        False,
                        (
                            {
                                "error":
                                "Failed to create a default tab for import."
                            },
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
            ({
                "error": "Failed to determine a target tab for import."
            }, 500),
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
        except sqlalchemy.exc.SQLAlchemyError as e_cleanup:
            db.session.rollback()
            logger.warning(
                "OPML import: Failed to cleanup empty default tab '%s': %s",
                _sanitize_for_log(tab_name),
                e_cleanup,
            )


def _parse_opml_root(opml_stream):
    """Parses the OPML stream and returns the root element."""
    try:
        # Use parse() directly on stream for better encoding handling
        tree = SafeET.parse(opml_stream)
        root = tree.getroot()
        return root, None
    except SafeET.ParseError as e:
        logger.error("OPML import failed: Malformed XML. Error: %s",
                     e,
                     exc_info=True)
        return None, (
            {
                "error": "Malformed OPML file. Please check the file format."
            },
            400,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(
            "OPML import failed: Could not parse file stream. Error: %s",
            e,
            exc_info=True,
        )
        return None, (
            {
                "error":
                "Could not parse OPML file. Please check the file format."
            },
            400,
        )


def _batch_commit_and_fetch_new_feeds(newly_added_feeds_list):
    """Commits new feeds and fetches them, with progress updates."""
    if not newly_added_feeds_list:
        return True, None

    try:
        db.session.commit()
        logger.info(
            "OPML import: Successfully batch-committed %s new feeds.",
            len(newly_added_feeds_list),
        )

        total_to_fetch = len(newly_added_feeds_list)
        for i, feed_obj in enumerate(newly_added_feeds_list):
            status_msg = f"Fetching new feed {i + 1}/{total_to_fetch}: {feed_obj.name}"
            # Phase 2 value: Processing Weight to 100
            if total_to_fetch > 0:
                progress_val = OPML_IMPORT_PROCESSING_WEIGHT + (
                    (i + 1) * OPML_IMPORT_FETCHING_WEIGHT // total_to_fetch)
            else:
                progress_val = 100

            # Only announce if significant progress or first/last
            should_announce = i == 0 or i == total_to_fetch - 1 or (i +
                                                                    1) % 5 == 0

            if should_announce:
                event_data = {
                    "type": "progress",
                    "status": status_msg,
                    "value": progress_val,
                    "max": 100,
                }
                announcer.announce(msg=f"data: {json.dumps(event_data)}\n\n")

            if feed_obj.id:
                try:
                    fetch_and_update_feed(feed_obj.id)
                except Exception:  # pylint: disable=broad-exception-caught
                    logger.exception(
                        "OPML import: Error fetching for new feed %s (ID: %s)",
                        feed_obj.name,
                        feed_obj.id,
                    )
            else:
                logger.error(
                    "OPML import: Feed '%s' missing ID after commit.",
                    _sanitize_for_log(feed_obj.name),
                )
        return True, None
    except sqlalchemy.exc.SQLAlchemyError:
        db.session.rollback()
        logger.exception("OPML import: Database commit failed for new feeds")
        return False, (
            {
                "error": "Database error during final feed import step."
            },
            500,
        )


def _invalidate_import_caches(affected_tab_ids_set):
    """Invalidates caches for all tabs affected by the import."""
    if not affected_tab_ids_set:
        return
    for tab_id in affected_tab_ids_set:
        invalidate_tab_feeds_cache(tab_id, invalidate_tabs=False)
    invalidate_tabs_cache()
    logger.info(
        "OPML import: Invalidated caches for tabs: %s.",
        affected_tab_ids_set,
    )


def import_opml(opml_file_stream, requested_tab_id_str):
    """Imports feeds from an OPML file, sending progress via SSE."""
    root, error_resp = _parse_opml_root(opml_file_stream)
    if error_resp:
        return None, error_resp

    total_outlines = len(root.findall(".//outline"))
    (
        top_level_target_tab_id,
        top_level_target_tab_name,
        was_default_tab_created,
        error_resp,
    ) = _determine_target_tab(requested_tab_id_str)
    if error_resp:
        return None, error_resp

    opml_body = root.find("body")
    if opml_body is None:
        logger.warning("OPML import: No <body> element found.")
        result = {
            "message": "No feeds found in OPML (missing body).",
            "imported_count": 0,
            "skipped_count": 0,
            "tab_id": top_level_target_tab_id,
            "tab_name": top_level_target_tab_name,
        }
        announcer.announce(
            msg=f"data: {json.dumps({'type': 'progress_complete', 'status': result['message']})}\n\n"
        )
        return result, None

    all_existing_feed_urls_set = {feed.url for feed in Feed.query.all()}

    # Announce start
    announcer.announce(
        msg=f"data: {json.dumps({'type': 'progress', 'status': 'Starting OPML import...', 'value': 0, 'max': 100})}\n\n"
    )

    state = _process_opml_outlines_iterative(
        list(opml_body),
        top_level_target_tab_id,
        top_level_target_tab_name,
        all_existing_feed_urls_set,
        total_outlines,
    )

    # Batch commit and fetch
    success, error_resp = _batch_commit_and_fetch_new_feeds(
        state.newly_added_feeds_list)
    if not success:
        return None, error_resp

    # Cache invalidation
    _invalidate_import_caches(state.affected_tab_ids_set)

    # Cleanup if needed
    _cleanup_empty_default_tab(
        was_default_tab_created,
        top_level_target_tab_id,
        top_level_target_tab_name,
        state.affected_tab_ids_set,
    )

    if not opml_body.findall("outline") and not state.newly_added_feeds_list:
        logger.info(
            "OPML import: No <outline> elements found in the OPML body.")
        result = {
            "message": "No feed entries or folders found in the OPML file.",
            "imported_count": 0,
            "skipped_count": 0,
            "tab_id": top_level_target_tab_id,
            "tab_name": top_level_target_tab_name,
        }
        announcer.announce(
            msg=f"data: {json.dumps({'type': 'progress_complete', 'status': result['message']})}\n\n"
        )
        return result, None

    imported_final_count = state.imported_count
    skipped_final_count = state.skipped_count

    result = {
        "message":
        f"{imported_final_count} feeds imported. {skipped_final_count} skipped. "
        f"Tab: {top_level_target_tab_name}.",
        "imported_count":
        imported_final_count,
        "skipped_count":
        skipped_final_count,
        "tab_id":
        top_level_target_tab_id,
        "tab_name":
        top_level_target_tab_name,
        "affected_tab_ids":
        list(state.affected_tab_ids_set),
    }

    # Final 'complete' message for SSE
    announcer.announce(
        msg=f"data: {json.dumps({'type': 'progress_complete', 'status': result['message']})}\n\n"
    )

    return result, None


MAX_FEED_RESPONSE_BYTES = 10 * 1024 * 1024  # 10MB cap for feed responses

# Hard cap for concurrent fetches to avoid resource exhaustion
# 20 is suitable for typical small VPS instances (e.g., 4 vCPUs) handling I/O bound tasks
WORKER_FETCH_CAP = 20


# Maximum number of concurrent feed fetches
# I/O bound tasks can handle more workers than CPU cores
def _get_max_concurrent_fetches():
    """Calculates the maximum number of concurrent feed fetches.

    Returns:
        int: The maximum number of concurrent fetches.
    """
    try:
        cpu_count = os.cpu_count() or 1
    except (NotImplementedError, OSError):
        cpu_count = 1

    try:
        max_workers = int(os.environ.get("FEED_FETCH_MAX_WORKERS", 0))
    except (ValueError, TypeError):
        max_workers = 0

    if max_workers <= 0:
        # Default heuristic with safety cap for auto-configuration
        return min(cpu_count * 5, WORKER_FETCH_CAP)

    # Respect explicit user configuration, but enforce the hard cap
    return min(max_workers, WORKER_FETCH_CAP)


MAX_CONCURRENT_FETCHES = _get_max_concurrent_fetches()

# --- Helper Functions ---


def _validate_xml_safety(content):
    """
    Validates XML content for XXE vulnerabilities using defusedxml.
    Returns False if a security violation is detected or if parsing fails (fail-closed).
    Returns True IF AND ONLY IF the content is successfully validated and safe.

    Policy:
    - forbid_dtd=False: Allows the presence of a `<!DOCTYPE ...>` declaration (required for many valid RSS feeds).
    - forbid_entities=True: STRICTLY blocks any `<!ENTITY ...>` declarations within the DTD. This is the primary defense against internal entity expansion (Billion Laughs) and external entity injection.
    - forbid_external=True: STICTLY blocks all external DTDs or external entity references (e.g., `SYSTEM "..."`), preventing SSRF and file system access.

    Malformed XML or non-XML input that raises SAXParseException or UnicodeError
    is REJECTED (returns False) for safety.
    """
    try:
        # We use a no-op handler because we only care about the parsing process raising security exceptions
        handler = ContentHandler()
        defusedxml.sax.parseString(
            content,
            handler,
            forbid_dtd=False,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden) as e:
        logger.error("XML Security Violation detected: %s",
                     _sanitize_for_log(str(e)))
        return False
    except (SAXParseException, UnicodeError) as e:
        # SECURITY HARDENING: Fail closed on malformed XML.
        # If defusedxml cannot parse it, we do not bypass to feedparser.
        # This prevents attackers from constructing payloads that defusedxml chokes on
        # but feedparser/libxml2 might process unsafely (e.g. parser differentials).
        # We explicitly reject ANY malformed XML to guarantee safety over availability.
        # This means that valid but slightly malformed feeds might be rejected, but this is a
        # necessary trade-off for security against XXE and DoS vectors.
        if str(e):
            logger.warning(
                "XML Parsing failed during safety check (rejecting): %s",
                _sanitize_for_log(str(e)),
            )
        return False

    return True


def parse_published_time(entry):
    """Attempts to parse the published time from a feed entry.

    Args:
        entry (feedparser.FeedParserDict): A feedparser entry object.

    Returns:
        datetime.datetime: A datetime object representing the published time
                           (UTC aware). Falls back to the current UTC time if
                           parsing fails.
    """
    parsed_dt = None
    pub_parsed = getattr(entry, "published_parsed", None)
    if isinstance(pub_parsed, (list, tuple)) and len(pub_parsed) >= 6:
        try:
            parsed_dt = datetime.datetime(*pub_parsed[:6], tzinfo=timezone.utc)
        except (TypeError, ValueError):
            parsed_dt = None

    if parsed_dt is None:
        # Try common date fields using dateutil.parser
        for field in ["published", "updated", "created", "dc:date"]:
            parsed_dt = _get_dt_from_field(entry, field)
            if isinstance(parsed_dt, datetime.datetime):
                break
            parsed_dt = None

    if isinstance(parsed_dt, datetime.datetime):
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(
                parsed_dt) is None:
            return parsed_dt.replace(tzinfo=timezone.utc)
        return parsed_dt.astimezone(timezone.utc)

    return datetime.datetime.now(timezone.utc)


def _get_dt_from_field(entry, field):
    """Internal helper to extract a datetime from a specific entry field."""
    if not hasattr(entry, field):
        return None
    field_value = getattr(entry, field)
    if not field_value:
        return None
    try:
        return date_parser.parse(field_value)
    except (ValueError, TypeError, OverflowError):
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


# --- Core Feed Processing Functions ---


def validate_and_resolve_url(url):
    """Validates URL and resolves IP to prevent SSRF (returns safe IP or None)."""
    try:
        parsed = urlparse(url)
        if not (parsed.scheme in ("http", "https") and parsed.hostname):
            return None, None

        try:
            addr_info = socket.getaddrinfo(parsed.hostname, None)
        except socket.gaierror:
            if os.environ.get("TESTING") == "true":
                return ("127.0.0.1", parsed.hostname)
            return (None, None)

        for res in addr_info:
            ip_str = res[4][0]
            ip_obj = ipaddress.ip_address(ip_str.split("%")[0])
            if _is_safe_ip(ip_obj):
                return ip_str, parsed.hostname

            logger.warning(
                "Blocked SSRF attempt: %s://%s -> %s",
                parsed.scheme,
                parsed.hostname,
                ip_obj,
            )

        return (None, None)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error validating URL safety")
        return (None, None)


def _is_safe_ip(ip):
    """Checks if an IP address is safe (not private, loopback, etc.)."""
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


class SafeHTTPSConnection(http.client.HTTPSConnection):
    """
    Custom HTTPSConnection that connects to a specific 'safe_ip'
    but uses the original hostname for SNI and SSL validation.
    Prevents DNS Rebinding (TOCTOU) on HTTPS.

    This class ensures that the IP address validated in the check phase
    is the EXACT same IP address used for the connection, preventing
    an attacker from swapping the IP (DNS Rebinding) between check and use.
    """

    def __init__(
        self,
        host,
        safe_ip,
        **kwargs,
    ):
        super().__init__(
            host,
            **kwargs,
        )
        self.safe_ip = safe_ip

    def connect(self):
        # Override connect to force connection to self.safe_ip
        # Logic adapted from http.client.HTTPSConnection.connect

        # 1. Establish TCP connection to the SAFE IP
        self.sock = socket.create_connection((self.safe_ip, self.port),
                                             self.timeout, self.source_address)

        if self._tunnel_host:
            self._tunnel()

        # 2. Wrap socket with SSL using the ORIGINAL hostname for validation
        if self._context is None:
            self._context = ssl.create_default_context()

        self.sock = self._context.wrap_socket(
            self.sock,
            # This ensures SNI and Cert Check match the Host, not the IP
            server_hostname=self.host,
        )


class SafeHTTPConnection(http.client.HTTPConnection):
    """
    Custom HTTPConnection that connects to a specific 'safe_ip'.
    Prevents DNS Rebinding (TOCTOU) on HTTP.
    """

    def __init__(
        self,
        host,
        safe_ip,
        **kwargs,
    ):
        super().__init__(
            host,
            **kwargs,
        )
        self.safe_ip = safe_ip

    def connect(self):
        # Override connect to force connection to self.safe_ip
        self.sock = socket.create_connection((self.safe_ip, self.port),
                                             self.timeout, self.source_address)


class SafeHTTPHandler(urllib.request.HTTPHandler):
    """
    Handler that uses SafeHTTPConnection.
    WARNING: THIS HANDLER IS STATEFUL (`current_safe_ip`).
    IT MUST NOT BE SHARED ACROSS THREADS OR REQUESTS.
    INSTANTIATE A NEW HANDLER FOR EACH FETCH.
    """

    def __init__(self, safe_ip):
        self.safe_ip = safe_ip
        self.current_safe_ip = safe_ip
        super().__init__()

    def _get_connection(self, host, **kwargs):
        return SafeHTTPConnection(host, self.current_safe_ip, **kwargs)

    def http_open(self, req):
        self.current_safe_ip = getattr(req, "safe_ip", self.safe_ip)
        return self.do_open(self._get_connection, req)


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    """
    Handler that uses SafeHTTPSConnection.
    WARNING: THIS HANDLER IS STATEFUL (`current_safe_ip`).
    IT MUST NOT BE SHARED ACROSS THREADS OR REQUESTS.
    INSTANTIATE A NEW HANDLER FOR EACH FETCH.
    """

    def __init__(self, safe_ip):
        self.safe_ip = safe_ip
        self.current_safe_ip = safe_ip
        super().__init__()

    def _get_connection(self, host, **kwargs):
        # Callback to create our custom connection
        # NOTE: urllib's do_open doesn't pass the request object to the connection factory directly.
        # We need a way to pass it.
        # We rely on modifying SafeHTTPSHandler state in https_open.
        return SafeHTTPSConnection(host, self.current_safe_ip, **kwargs)

    def https_open(self, req):
        # Determine safe_ip for this request.
        # If it's a redirect, SafeRedirectHandler attached 'safe_ip' to 'req'.
        self.current_safe_ip = getattr(req, "safe_ip", self.safe_ip)
        return self.do_open(self._get_connection, req)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Custom RedirectHandler that validates the target URL of a redirect
    to prevent SSRF via redirection to unsafe IPs.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Handle relative redirects by joining with original URL
        absolute_newurl = urljoin(req.full_url, newurl)

        # Resolve and validate the NEW url
        safe_ip, _ = validate_and_resolve_url(absolute_newurl)
        if not safe_ip:
            logger.warning("Blocked unsafe redirect to: %s",
                           _sanitize_for_log(absolute_newurl))
            raise urllib.error.HTTPError(absolute_newurl, code,
                                         "Blocked unsafe redirect", headers,
                                         fp)

        # Create the new request
        new_req = super().redirect_request(req, fp, code, msg, headers,
                                           absolute_newurl)

        # PIN THE IP: Attach the resolved safe_ip to the new request
        # This allows SafeHTTPSHandler (and HTTP logic) to use the validated IP
        # without re-resolving (TOCTOU protection).
        if new_req:
            new_req.safe_ip = safe_ip

        return new_req


def _fetch_feed_content(feed_url):
    """Fetches and parses feed content from a given URL.

    This function is a wrapper around `fetch_feed` to handle exceptions
    when used in concurrent execution contexts. It is designed to be
    side-effect-free regarding the database.

    Args:
        feed_url (str): The URL of the feed to fetch.

    Returns:
        feedparser.FeedParserDict | None: The parsed feed object, or None if
        fetching or parsing failed.
    """
    try:
        parsed_feed = fetch_feed(feed_url)
        return parsed_feed
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error in fetch thread for feed %s",
                         _sanitize_for_log(feed_url))
        return None


def _process_fetch_result(feed_db_obj, parsed_feed):
    """
    Helper function to process the result of a feed fetch (parsed_feed).
    Handles empty feeds, database updates, and calling process_feed_entries.

    Args:
        feed_db_obj (Feed): The database feed object.
        parsed_feed (feedparser.FeedParserDict): The parsed feed result.

    Returns:
        tuple: (success, new_items_count, tab_id)
    """
    if not parsed_feed:
        logger.error(
            "Fetching content for feed '%s' (ID: %s) failed (None returned).",
            _sanitize_for_log(feed_db_obj.name),
            feed_db_obj.id,
        )
        return False, 0, feed_db_obj.tab_id

    # Handle cases where feed is fetched but has no entries (common for new or empty feeds)
    if not parsed_feed.entries:
        logger.info(
            "Feed '%s' (ID: %s) fetched successfully but contained no entries.",
            _sanitize_for_log(feed_db_obj.name),
            feed_db_obj.id,
        )
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        # CAREFUL: Extract attributes BEFORE rollback to avoid detached instance errors
        feed_name = feed_db_obj.name
        try:
            db.session.commit()
        except sqlalchemy.exc.SQLAlchemyError:
            db.session.rollback()
            logger.exception(
                "Error committing feed update (no entries) for %s",
                _sanitize_for_log(feed_name),
            )
            # Still, the fetch itself might be considered a "success" in terms of reachability
        return True, 0, feed_db_obj.tab_id

    try:
        new_items = process_feed_entries(feed_db_obj, parsed_feed)
        # process_feed_entries handles its own logging and commits for items and last_updated_time.
        return True, new_items, feed_db_obj.tab_id
    except Exception:  # pylint: disable=broad-exception-caught
        # CAREFUL: Extract attributes BEFORE rollback to avoid detached instance errors
        feed_name = feed_db_obj.name
        feed_id = feed_db_obj.id
        db.session.rollback()
        logger.exception(
            "An unexpected error occurred during entry processing for feed '%s' (ID: %s)",
            _sanitize_for_log(feed_name),
            feed_id,
        )
        return False, 0, feed_db_obj.tab_id


def fetch_feed(feed_url):
    """Fetches and parses a feed, preventing SSRF via IP pinning."""
    safe_ip, _ = validate_and_resolve_url(feed_url)
    if not safe_ip:
        return None

    logger.info("Fetching feed: %s", _sanitize_for_log(feed_url))
    try:
        # Prevent TOCTOU: Use custom handlers to force connection to safe_ip

        # Register BOTH handlers to ensure safety during redirects (HTTPS -> HTTP or HTTP -> HTTPS)
        # Both handlers utilize ip pinning via `safe_ip` (and `req.safe_ip` for redirects).
        http_handler = SafeHTTPHandler(safe_ip=safe_ip)
        https_handler = SafeHTTPSHandler(safe_ip=safe_ip)
        redirect_handler = SafeRedirectHandler()

        # Build opener with all handlers
        opener = urllib.request.build_opener(http_handler, https_handler,
                                             redirect_handler)

        req = urllib.request.Request(
            feed_url,
            headers={
                "User-Agent": "SheepVibes/1.0",
                "Accept-Encoding": "identity",  # Prevent Zip Bombs
            },
        )
        url_opener = opener.open(req, timeout=10)

        with url_opener as response:
            # Check Content-Length header first
            content_length = response.getheader("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_FEED_RESPONSE_BYTES:
                        logger.warning(
                            "Feed rejected: Content-Length (%s) exceeds limit (%s) for %s",
                            _sanitize_for_log(content_length),
                            MAX_FEED_RESPONSE_BYTES,
                            _sanitize_for_log(feed_url),
                        )
                        return None
                except (ValueError, TypeError):
                    # Malformed header; ignore and rely on read limit
                    logger.warning(
                        "Ignored invalid Content-Length (%s) for feed %s",
                        _sanitize_for_log(content_length),
                        _sanitize_for_log(feed_url),
                    )

            # Read limited amount + 1 byte to detect overflow
            content = response.read(MAX_FEED_RESPONSE_BYTES + 1)
            if len(content) > MAX_FEED_RESPONSE_BYTES:
                logger.warning(
                    "Feed rejected: Response size exceeds limit (%s) for %s",
                    MAX_FEED_RESPONSE_BYTES,
                    _sanitize_for_log(feed_url),
                )
                return None

        # ZIP BOMB PROTECTION
        # Even with 'Accept-Encoding: identity', some servers might send GZIP.
        # We manually check for the GZIP magic header (\x1f\x8b) and reject.
        if content.startswith(b"\x1f\x8b"):
            logger.warning(
                "Feed rejected: Compressed content detected (Zip Bomb protection) for %s",
                _sanitize_for_log(feed_url),
            )
            return None

        if not _validate_xml_safety(content):
            # Sanitize URL for logging to prevent log injection
            safe_log_url = _sanitize_for_log(feed_url)
            logger.warning("Feed rejected due to security violation: %s",
                           safe_log_url)
            return None

        parsed_feed = feedparser.parse(content)
        # feedparser.parse(bytes) doesn't set bozo for network errors, but we handled network above.
        if parsed_feed.bozo:
            # Check for bozo_exception and sanitize it (it can contain malicious input)
            bozo_exc = parsed_feed.get("bozo_exception")
            safe_exc_msg = _sanitize_for_log(
                str(bozo_exc)) if bozo_exc else "Unknown"
            logger.warning("Feed parsing warning: %s", safe_exc_msg)

        return parsed_feed

    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Error fetching feed %s", _sanitize_for_log(feed_url))
        return None


# --- Feed Processing Helpers ---


def _update_feed_metadata(feed_db_obj, parsed_feed):
    """Updates feed title and site_link if changed.

    Args:
        feed_db_obj (Feed): The database feed object.
        parsed_feed (feedparser.FeedParserDict): The parsed feed result.
    """
    raw_title = parsed_feed.feed.get("title")
    new_title = raw_title.strip() if raw_title else None
    if new_title and new_title != feed_db_obj.name:
        logger.info(
            "Updating feed title for '%s' to '%s'",
            _sanitize_for_log(feed_db_obj.name),
            _sanitize_for_log(new_title),
        )
        feed_db_obj.name = new_title

    raw_site_link = parsed_feed.feed.get("link")
    new_site_link = validate_link_structure(raw_site_link)
    if not new_site_link and raw_site_link:
        logger.warning(
            "Feed '%s': Ignored potentially unsafe site_link: %s",
            _sanitize_for_log(feed_db_obj.name),
            _sanitize_for_log(raw_site_link),
        )

    if new_site_link and new_site_link != feed_db_obj.site_link:
        logger.info(
            "Updating feed site_link for '%s' from '%s' to '%s'",
            _sanitize_for_log(feed_db_obj.name),
            _sanitize_for_log(feed_db_obj.site_link),
            _sanitize_for_log(new_site_link),
        )
        feed_db_obj.site_link = new_site_link


def _collect_new_items(feed_db_obj, parsed_feed):
    """Identifies new items to add and updates existing ones."""
    items_to_add = []
    batch_processed_guids = set()
    batch_processed_links = set()

    # Optimization: Query only necessary columns to avoid loading full objects
    # item[1] is guid, item[2] is link, item[3] is title
    items_tuple = (db.session.query(
        FeedItem.id, FeedItem.guid, FeedItem.link,
        FeedItem.title).filter_by(feed_id=feed_db_obj.id).all())

    # Create lookup maps
    existing_items_by_guid = {it.guid: it for it in items_tuple if it.guid}
    existing_items_by_link = {it.link: it for it in items_tuple if it.link}

    logger.info(
        "Processing %s entries for feed: %s (ID: %s)",
        len(parsed_feed.entries),
        _sanitize_for_log(feed_db_obj.name),
        feed_db_obj.id,
    )

    # Pre-calculate dates to avoid double parsing and ensure consistency between
    # sorting and storage (e.g. if parse_published_time uses current time as fallback).
    entries_with_dates = []
    for entry in parsed_feed.entries:
        entries_with_dates.append((entry, parse_published_time(entry)))

    # Sort entries by published date (newest first).
    # Our "First Wins" deduplication strategy (below) will preserve the version
    # that appears first in the iteration. Sorting ensures the most recently
    # published version is processed first and thus preserved in case of duplicates.
    try:
        entries_with_dates.sort(key=lambda x: x[1], reverse=True)
    except Exception:  # pylint: disable=broad-exception-caught
        # If sorting fails, proceed with original order.
        logger.warning("Failed to sort entries for feed %s",
                       _sanitize_for_log(feed_db_obj.name))

    for entry, parsed_published in entries_with_dates:
        raw_link = entry.get("link")
        entry_link = validate_link_structure(raw_link)

        if not entry_link:
            logger.warning(
                "Skipping entry titled '%s' for feed '%s' due to missing link.",
                _sanitize_for_log(entry.get("title", "[No Title]")[:100]),
                _sanitize_for_log(feed_db_obj.name),
            )
            continue

        # SECURITY & LOGIC: Generate a robust GUID if missing.
        # Fallback to hash of link+title to distinguish items pointing to same URL (e.g. Kernel versions).
        if entry.get("id"):
            db_guid = entry.get("id")
        else:
            # Create a synthetic GUID based on link and title to ensure uniqueness
            # for items that share a link but have different content.
            unique_string = f"{entry_link}{entry.get('title', '')}"

            db_guid = hashlib.sha256(unique_string.encode("utf-8")).hexdigest()

        # Check existing
        existing_match = existing_items_by_guid.get(db_guid)
        if not existing_match:
            # Minimal fallback: Check by link ONLY if we used link as GUID (legacy)
            # or if we really want to strict de-dupe.
            # But for now, let's rely on our robust GUID.
            # We still check existing_items_by_link just in case we have old DB entries
            # that were saved with just the link as GUID?
            # Actually, standard behavior is to trust the GUID.
            # If we change how GUID is generated, we might duplicate old items once.
            # This is acceptable to fix the regression.
            existing_match = existing_items_by_link.get(entry_link)

        if existing_match:
            _update_existing_item(
                feed_db_obj,
                existing_match,
                entry.get("title", "[No Title]"),
                entry_link,
            )
            continue

        # Check batch duplicates
        if _is_batch_duplicate(
                db_guid,
                batch_processed_guids,
                feed_db_obj.name,
        ):
            continue

        if db_guid:
            batch_processed_guids.add(db_guid)
        batch_processed_links.add(entry_link)

        items_to_add.append(
            FeedItem(
                feed_id=feed_db_obj.id,
                title=entry.get("title", "[No Title]"),
                link=entry_link,
                published_time=parsed_published,
                guid=db_guid,
            ))

    return items_to_add


def _update_existing_item(feed_db_obj, existing_item_data, entry_title,
                          entry_link):
    """Updates an existing item if title or link changed.

    Args:
        feed_db_obj (Feed): The database feed object.
        existing_item_data (Row): Tuple-like object with existing item ID, title, and link.
        entry_title (str): New title from the feed entry.
        entry_link (str): New link from the feed entry.
    """
    existing_title = existing_item_data.title
    existing_link = existing_item_data.link

    updates = {}
    if entry_title and entry_title != existing_title:
        updates["title"] = entry_title

    if entry_link and entry_link != existing_link:
        updates["link"] = entry_link

    if updates:
        logger.info(
            "Updating fields %s for existing item '%s' in feed '%s'",
            list(updates.keys()),
            _sanitize_for_log(existing_title),
            _sanitize_for_log(feed_db_obj.name),
        )
        db.session.query(FeedItem).filter(
            FeedItem.id == existing_item_data.id).update(
                updates, synchronize_session=False)


def _is_batch_duplicate(db_guid, batch_guids, feed_name):
    """Checks if an item is a duplicate within the current processing batch.

    Args:
        db_guid (str): Calculated GUID for the item.
        batch_guids (set): Set of GUIDs processed in current batch.
        feed_name (str): Name of the feed for logging.

    Returns:
        bool: True if it's a duplicate, False otherwise.
    """
    if db_guid and db_guid in batch_guids:
        logger.warning(
            "Skipping duplicate item (GUID: %s) in batch for feed '%s'.",
            _sanitize_for_log(db_guid),
            _sanitize_for_log(feed_name),
        )
        return True

    # RELAXATION: Do not strict dedupe by link alone.
    # We rely on the robust GUID (which includes Title) to catch duplicates.
    # if entry_link in batch_links: ... -> REMOVED

    return False


def _save_items_to_db(feed_db_obj, items_to_add):
    """Commits new items to the database, handling batch failures."""
    committed_count = 0
    try:
        db.session.add_all(items_to_add)
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        db.session.commit()
        committed_count = len(items_to_add)
        logger.info(
            "Successfully batch-added %s new items for feed: %s",
            committed_count,
            _sanitize_for_log(feed_db_obj.name),
        )
    except IntegrityError as e:
        db.session.rollback()
        logger.warning(
            "Batch insert failed for feed '%s': %s. Retrying individually.",
            _sanitize_for_log(feed_db_obj.name),
            _sanitize_for_log(str(e)),
        )
        committed_count = _save_items_individually(feed_db_obj, items_to_add)
    except sqlalchemy.exc.SQLAlchemyError:
        db.session.rollback()
        logger.exception(
            "Generic error committing new items for feed %s",
            _sanitize_for_log(feed_db_obj.name),
        )
        return 0

    return committed_count


def _save_items_individually(feed_db_obj, items_to_add):
    """Helper to save items one by one after a batch failure."""
    # Ensure last_updated_time is updated even if items fail
    try:
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        db.session.add(feed_db_obj)
        db.session.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        logger.exception(
            "Error updating last_updated_time for feed '%s' after batch failure",
            _sanitize_for_log(feed_db_obj.name),
        )
        db.session.rollback()  # Rollback if updating last_updated_time fails

    count = 0
    for item in items_to_add:
        try:
            db.session.add(item)
            db.session.commit()
            count += 1
            logger.debug("Individually added item: %s",
                         _sanitize_for_log(item.title[:50]))
        except IntegrityError as ie:
            db.session.rollback()
            logger.error(
                "Failed to add item '%s' for feed '%s' (link: %s, guid: %s): %s",
                _sanitize_for_log(item.title[:100]),
                _sanitize_for_log(feed_db_obj.name),
                _sanitize_for_log(item.link),
                _sanitize_for_log(item.guid),
                _sanitize_for_log(str(ie)),
            )
        except sqlalchemy.exc.SQLAlchemyError:
            db.session.rollback()
            logger.exception(
                "Generic error adding item '%s'",
                _sanitize_for_log(item.title[:100]),
            )

    if count > 0:
        logger.info(
            "Recovered %s items individually for feed: %s",
            count,
            _sanitize_for_log(feed_db_obj.name),
        )
    else:
        logger.info(
            "No items added individually for feed: %s",
            _sanitize_for_log(feed_db_obj.name),
        )

    return count


def _enforce_feed_limit(feed_db_obj):
    """Enforces MAX_ITEMS_PER_FEED by evicting oldest items.

    Optimization: Identify items to evict by offsetting from the newest items,
    avoiding a separate COUNT(*) query.
    """
    # We want to keep the newest MAX_ITEMS_PER_FEED items.
    # Anything beyond that (ordered by newest first) should be evicted.
    # We use offset() to skip the newest items and select the rest.

    # Fetch IDs to evict.
    # We use .limit(1000) instead of .limit(-1) or .limit(None) to:
    # 1. Provide a bounded result set, avoiding OOM on massive feeds.
    # 2. Avoid SQLite-specific LIMIT -1 behavior.
    # This means we only delete up to 1000 items per update, which acts as eventual consistency.
    ids_to_evict_rows = (db.session.query(
        FeedItem.id).filter_by(feed_id=feed_db_obj.id).order_by(
            FeedItem.published_time.desc().nullslast(),
            FeedItem.fetched_time.desc().nullslast(),
            FeedItem.id.desc(),
    ).offset(MAX_ITEMS_PER_FEED).limit(1000).all())

    if not ids_to_evict_rows:
        return

    ids_to_evict = [r.id for r in ids_to_evict_rows]

    # Chunk the deletions to avoid hitting SQLite's parameter limit (default 999)
    chunk_size = DELETE_CHUNK_SIZE
    deleted_count = 0
    for i in range(0, len(ids_to_evict), chunk_size):
        chunk = ids_to_evict[i:i + chunk_size]
        deleted_count += (db.session.query(FeedItem).filter(
            FeedItem.id.in_(chunk)).delete(synchronize_session=False))

    if deleted_count > 0:
        logger.info(
            "Evicted %s oldest items from feed '%s'.",
            deleted_count,
            _sanitize_for_log(feed_db_obj.name),
        )
        try:
            db.session.commit()
        except sqlalchemy.exc.SQLAlchemyError:
            db.session.rollback()
            logger.exception(
                "Error committing eviction for feed '%s'",
                _sanitize_for_log(feed_db_obj.name),
            )


def process_feed_entries(feed_db_obj, parsed_feed):
    """Processes entries from a parsed feed and adds new items to the database.

    Args:
        feed_db_obj (Feed): The Feed database object (SQLAlchemy model instance).
        parsed_feed (feedparser.FeedParserDict): The dictionary object returned
                                                 by feedparser.parse().

    Returns:
        int: The number of new items added to the database for this feed.
    """
    if not parsed_feed:
        logger.error(
            "process_feed_entries called with a null parsed_feed for feed ID %s",
            feed_db_obj.id if feed_db_obj else "Unknown",
        )
        return 0

    _update_feed_metadata(feed_db_obj, parsed_feed)
    items_to_add = _collect_new_items(feed_db_obj, parsed_feed)

    # Commit metadata and existing item updates immediately.
    # This ensures they are preserved even if the batch insert of new items fails later.
    try:
        db.session.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        db.session.rollback()
        logger.exception(
            "Error committing metadata/existing items for feed %s",
            _sanitize_for_log(feed_db_obj.name),
        )
        # It's safer to stop processing this feed to avoid potential inconsistencies
        # if the metadata/update commit failed.
        return 0

    if not items_to_add:
        # If no new items, we are done.
        # last_updated_time is usually updated on successful commit of items,
        # or here if there were no items but fetch succeeded.
        feed_db_obj.last_updated_time = datetime.datetime.now(timezone.utc)
        try:
            db.session.commit()
        except sqlalchemy.exc.SQLAlchemyError:
            db.session.rollback()
            logger.exception(
                "Error committing feed update (no new items) for %s",
                _sanitize_for_log(feed_db_obj.name),
            )
        return 0

    committed_items_count = _save_items_to_db(feed_db_obj, items_to_add)
    _enforce_feed_limit(feed_db_obj)

    return committed_items_count


def fetch_and_update_feed(feed_id):
    """Fetches a single feed by ID and updates the database.

    Args:
        feed_id (int): The database ID of the Feed to update.

    Returns:
        tuple (bool, int, int): (success, new_items_count, tab_id)
    """
    feed = db.session.get(Feed, feed_id)
    if not feed:
        logger.error("Feed with ID %s not found for update.", feed_id)
        return False, 0, None

    # fetch_feed already handles errors and returns None, but logic here checks return
    parsed_feed = _fetch_feed_content(feed.url)

    # Delegate processing to helper
    return _process_fetch_result(feed, parsed_feed)


def update_all_feeds():
    """Fetches all feeds in parallel, with progress updates, and processes entries.

    Returns:
        tuple (int, int, set): (successful_count, total_new_items, affected_tab_ids)
    """
    all_feeds = Feed.query.all()
    total_feeds = len(all_feeds)
    processed_count = 0
    successful_count = 0
    total_new_items = 0
    affected_tab_ids = set()

    logger.info("Starting update process for %d feeds (Parallelized).",
                total_feeds)
    announcer.announce(
        msg=f"data: {json.dumps({'type': 'progress', 'status': 'Starting feed refresh...', 'value': 0, 'max': total_feeds})}\n\n"
    )

    actual_workers = min(MAX_CONCURRENT_FETCHES,
                         total_feeds) if all_feeds else 1
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=actual_workers) as executor:
        future_to_feed = {
            executor.submit(_fetch_feed_content, feed.url): feed
            for feed in all_feeds
        }

        for future in concurrent.futures.as_completed(future_to_feed):
            feed_obj = future_to_feed[future]
            processed_count += 1
            status_msg = f"({processed_count}/{total_feeds}) Checking: {feed_obj.name}"
            announcer.announce(
                msg=f"data: {json.dumps({'type': 'progress', 'status': status_msg, 'value': processed_count, 'max': total_feeds})}\n\n"
            )

            try:
                parsed_feed = future.result()
                success, new_items, tab_id = _process_fetch_result(
                    feed_obj, parsed_feed)
                if success:
                    successful_count += 1
                    total_new_items += new_items
                    if new_items > 0:
                        affected_tab_ids.add(tab_id)
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Critical error processing future for feed %s (%s)",
                    _sanitize_for_log(feed_obj.name),
                    feed_obj.id,
                )

    logger.info(
        "Finished updating feeds. Successful: %d/%d, New Items: %s",
        successful_count,
        total_feeds,
        total_new_items,
    )
    # Final 'complete' message
    announcer.announce(
        msg=f"data: {json.dumps({'type': 'progress_complete', 'status': 'Refresh complete.'})}\n\n"
    )
    return successful_count, total_new_items, affected_tab_ids
