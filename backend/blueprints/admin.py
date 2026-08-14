"""Blueprint for administrative management and system diagnostics."""

import datetime
import io
import logging
import os
import platform
import re
import sqlite3
import tempfile

from flask import Blueprint, current_app, jsonify, request, send_file
from sqlalchemy import func

from ..auth import admin_required, get_current_user, login_required
from ..cache_utils import invalidate_user_caches
from ..extensions import cache, db
from ..models import Feed, FeedItem, Tab, User

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")


@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users():
    """Lists all registered users with feed and tab usage counts."""
    users = User.query.order_by(User.id).all()
    user_list = []

    for user in users:
        tabs_count = Tab.query.filter_by(user_id=user.id).count()
        feeds_count = Feed.query.join(Tab).filter(Tab.user_id == user.id).count()
        user_dict = user.to_dict()
        user_dict["tabs_count"] = tabs_count
        user_dict["feeds_count"] = feeds_count
        user_list.append(user_dict)

    return jsonify({"users": user_list}), 200


@admin_bp.route("/users", methods=["POST"])
@admin_required
def create_user():
    """Creates a new user account with default tabs."""
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    username = str(data.get("username")).strip()
    password = str(data.get("password"))
    email = str(data.get("email")).strip() if data.get("email") else None
    role = str(data.get("role", "user")).strip().lower()

    if not USERNAME_REGEX.match(username):
        return (
            jsonify(
                {
                    "error": (
                        "Username must be 3-30 characters long and contain only "
                        "letters, numbers, underscores, and hyphens"
                    )
                }
            ),
            400,
        )

    if len(password) < 8:
        return (
            jsonify({"error": "Password must be at least 8 characters long"}),
            400,
        )

    if role not in ("user", "admin"):
        return jsonify({"error": "Role must be 'user' or 'admin'"}), 400

    # Check for username collision (case-insensitive)
    existing_user = User.query.filter(
        func.lower(User.username) == username.lower()
    ).first()
    if existing_user:
        return jsonify({"error": f"Username '{username}' is already taken"}), 409

    new_user = User(
        username=username,
        email=email,
        role=role,
        is_active=True,
    )
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.flush()

    # Create default tab for the user
    default_tab = Tab(name="General", order=0, user_id=new_user.id)
    db.session.add(default_tab)
    db.session.commit()

    logger.info("Admin created user: %s (ID: %d, Role: %s)", username, new_user.id, role)

    user_dict = new_user.to_dict()
    user_dict["tabs_count"] = 1
    user_dict["feeds_count"] = 0

    return (
        jsonify({"message": "User created successfully", "user": user_dict}),
        201,
    )


@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@admin_required
def update_user(user_id):
    """Updates an existing user's role, status, email, or resets their password."""
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    current_admin = get_current_user()
    data = request.get_json() or {}

    # Update is_active
    if "is_active" in data:
        new_status = bool(data["is_active"])
        if not new_status and target_user.id == current_admin.id:
            return (
                jsonify({"error": "Cannot deactivate your own administrator account"}),
                400,
            )
        target_user.is_active = new_status

    # Update role
    if "role" in data:
        new_role = str(data["role"]).strip().lower()
        if new_role not in ("user", "admin"):
            return jsonify({"error": "Role must be 'user' or 'admin'"}), 400
        if new_role != "admin" and target_user.id == current_admin.id:
            return (
                jsonify({"error": "Cannot demote your own administrator account"}),
                400,
            )
        target_user.role = new_role

    # Update password
    if "password" in data and data["password"]:
        new_password = str(data["password"])
        if len(new_password) < 8:
            return (
                jsonify({"error": "Password must be at least 8 characters long"}),
                400,
            )
        target_user.set_password(new_password)

    # Update email
    if "email" in data:
        email_val = str(data["email"]).strip() if data["email"] else None
        target_user.email = email_val

    # Update username
    if "username" in data and data["username"]:
        new_username = str(data["username"]).strip()
        if new_username.lower() != target_user.username.lower():
            if not USERNAME_REGEX.match(new_username):
                return (
                    jsonify(
                        {
                            "error": (
                                "Username must be 3-30 characters long and contain only "
                                "letters, numbers, underscores, and hyphens"
                            )
                        }
                    ),
                    400,
                )
            existing = User.query.filter(
                func.lower(User.username) == new_username.lower()
            ).first()
            if existing:
                return (
                    jsonify({"error": f"Username '{new_username}' is already taken"}),
                    409,
                )
            target_user.username = new_username

    db.session.commit()
    invalidate_user_caches(target_user.id)
    logger.info("Admin updated user: %s (ID: %d)", target_user.username, target_user.id)

    tabs_count = Tab.query.filter_by(user_id=target_user.id).count()
    feeds_count = Feed.query.join(Tab).filter(Tab.user_id == target_user.id).count()
    user_dict = target_user.to_dict()
    user_dict["tabs_count"] = tabs_count
    user_dict["feeds_count"] = feeds_count

    return (
        jsonify({"message": "User updated successfully", "user": user_dict}),
        200,
    )


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    """Deletes a user account and cascades all associated tabs and feeds."""
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    current_admin = get_current_user()
    if target_user.id == current_admin.id:
        return jsonify({"error": "Cannot delete your own administrator account"}), 400

    username = target_user.username
    invalidate_user_caches(target_user.id)

    db.session.delete(target_user)
    db.session.commit()

    logger.info("Admin deleted user: %s (ID: %d)", username, user_id)
    return jsonify({"message": f"User '{username}' deleted successfully"}), 200


@admin_bp.route("/system/stats", methods=["GET"])
@admin_required
def system_stats():
    """Returns system diagnostic information and usage statistics."""
    users_count = User.query.count()
    tabs_count = Tab.query.count()
    feeds_count = Feed.query.count()
    items_count = FeedItem.query.count()
    unread_items_count = FeedItem.query.filter_by(is_read=False).count()

    # Determine database size
    db_size_bytes = 0
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if db_uri.startswith("sqlite:////") or (
        db_uri.startswith("sqlite:///") and not db_uri.startswith("sqlite:///:memory:") and "mode=memory" not in db_uri
    ):
        file_path = db_uri.replace("sqlite:///", "")
        if "?" in file_path:
            file_path = file_path.split("?")[0]
        if os.path.exists(file_path):
            try:
                db_size_bytes = os.path.getsize(file_path)
            except OSError:
                pass

    # Check cache status
    cache_type = current_app.config.get("CACHE_TYPE", "NullCache")
    cache_status = "active"
    try:
        cache.set("admin_health_check_key", "ok", timeout=5)
        if cache.get("admin_health_check_key") != "ok":
            cache_status = "degraded"
    except Exception as e:
        logger.warning("Cache health check failed: %s", e)
        cache_status = "unavailable"

    stats = {
        "users_count": users_count,
        "tabs_count": tabs_count,
        "feeds_count": feeds_count,
        "items_count": items_count,
        "unread_items_count": unread_items_count,
        "db_size_bytes": db_size_bytes,
        "cache_type": cache_type,
        "cache_status": cache_status,
        "python_version": platform.python_version(),
        "server_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    return jsonify({"stats": stats}), 200


@admin_bp.route("/backup", methods=["GET"])
@admin_required
def download_backup():
    """Generates and downloads a point-in-time snapshot backup of the SQLite database."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    download_filename = f"sheepvibes_backup_{timestamp}.db"

    try:
        temp_backup = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        temp_backup_path = temp_backup.name
        temp_backup.close()

        raw_conn = db.engine.raw_connection()
        driver_conn = raw_conn.driver_connection if hasattr(raw_conn, "driver_connection") else raw_conn.connection
        dest_conn = sqlite3.connect(temp_backup_path)
        driver_conn.backup(dest_conn)
        dest_conn.close()

        return send_file(
            temp_backup_path,
            mimetype="application/x-sqlite3",
            as_attachment=True,
            download_name=download_filename,
        )
    except Exception as e:
        logger.error("Failed to generate database backup: %s", e)
        return jsonify({"error": f"Failed to generate backup: {str(e)}"}), 500
