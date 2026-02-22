"""Blueprint for OPML import and export operations."""

import logging
import os
import xml.etree.ElementTree as ET

from filelock import FileLock, Timeout
from flask import Blueprint, Response, current_app, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from ..feed_service import import_opml as import_opml_service
from ..models import Feed, Subscription, Tab

opml_bp = Blueprint("opml", __name__, url_prefix="/api/opml")
logger = logging.getLogger(__name__)


def _generate_opml_string(user_id):
    """Generates the OPML string from the database for a specific user."""
    opml_element = ET.Element("opml", version="2.0")
    head_element = ET.SubElement(opml_element, "head")
    title_element = ET.SubElement(head_element, "title")
    title_element.text = "SheepVibes Feeds"
    body_element = ET.SubElement(opml_element, "body")

    # Eager load subscriptions and feeds to avoid N+1 queries
    tabs = (
        Tab.query.filter_by(user_id=user_id)
        .options(selectinload(Tab.subscriptions).selectinload(Subscription.feed))
        .order_by(Tab.order)
        .all()
    )

    feed_count = 0
    tab_count = 0

    for tab in tabs:
        if not tab.subscriptions:
            continue

        folder_outline = ET.SubElement(body_element, "outline")
        folder_outline.set("text", tab.name)
        folder_outline.set("title", tab.name)

        tab_count += 1
        sorted_subs = sorted(
            tab.subscriptions, key=lambda s: (
                s.order, (s.custom_name or s.feed.name))
        )

        for sub in sorted_subs:
            feed_outline = ET.SubElement(folder_outline, "outline")
            feed_name = sub.custom_name or sub.feed.name
            feed_outline.set("text", feed_name)
            feed_outline.set("title", feed_name)
            feed_outline.set("xmlUrl", sub.feed.url)
            feed_outline.set("type", "rss")
            if sub.feed.site_link:
                feed_outline.set("htmlUrl", sub.feed.site_link)
            feed_count += 1

    opml_string = ET.tostring(opml_element, encoding="utf-8", method="xml").decode(
        "utf-8"
    )

    return opml_string, tab_count, feed_count


@opml_bp.route("/import", methods=["POST"])
@login_required
def import_opml():
    """Imports feeds from an OPML file for the current user."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    opml_file = request.files["file"]
    if opml_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Validate file size (max 5MB)
    content = opml_file.read()
    if len(content) > 5 * 1024 * 1024:
        return jsonify({"error": "File is too large (max 5MB)"}), 400
    opml_file.seek(0)

    # Validate file extension
    _, ext = os.path.splitext(opml_file.filename)
    if ext.lower() not in {".opml", ".xml"}:
        return (
            jsonify({"error": "Invalid file type. Allowed: .opml, .xml"}),
            400,
        )

    requested_tab_id_str = request.form.get("tab_id")

    # Call the service function - needs to be updated for multi-user
    result, error_info = import_opml_service(
        opml_file.stream, requested_tab_id_str, current_user.id
    )

    if error_info:
        error_json, status_code = error_info
        return jsonify(error_json), status_code

    return jsonify(result), 200


@opml_bp.route("/export", methods=["GET"])
@login_required
def export_opml():
    """Exports the current user's feeds as an OPML file."""
    try:
        opml_string, tab_count, feed_count = _generate_opml_string(
            current_user.id)
    except SQLAlchemyError:
        logger.exception("Database error during OPML generation for export")
        return jsonify({"error": "Database error during OPML generation"}), 500

    response = Response(opml_string, mimetype="application/xml")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="sheepvibes_feeds_{current_user.username}.opml"'
    )
    return response


def autosave_opml():
    """Saves ALL users' feeds as OPML backups (maybe one per user or one global).
    For now, let's just disable or implement a simple version.
    Actually, autosave in a multi-user app should probably be handled differently.
    """
    # Placeholder for autosave logic if still needed.
    # For now, let's keep it simple and skip it to avoid complexity.
    pass
