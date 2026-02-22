import logging
import os
import sqlite3
import tempfile
from functools import wraps

from flask import Blueprint, current_app, jsonify, send_file
from flask_login import current_user, login_required

from ..extensions import db
from ..models import User

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


@admin_bp.route("/users", methods=["GET"])
@login_required
@admin_required
def list_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({"error": "Cannot delete yourself"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    deleted_username = user.username
    db.session.delete(user)
    db.session.commit()
    logger.info("Admin %s deleted user %s",
                current_user.username, deleted_username)
    return jsonify({"message": f"User {deleted_username} deleted"}), 200


@admin_bp.route("/users/<int:user_id>/toggle-admin", methods=["POST"])
@login_required
@admin_required
def toggle_admin(user_id):
    if current_user.id == user_id:
        return jsonify({"error": "Cannot toggle admin status for yourself"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.is_admin = not user.is_admin
    db.session.commit()
    logger.info(
        "Admin %s toggled admin status for user %s to %s",
        current_user.username,
        user.username,
        user.is_admin,
    )
    return jsonify(user.to_dict()), 200


@admin_bp.route("/export-db", methods=["GET"])
@login_required
@admin_required
def export_db():
    """Export the SQLite database as a safe backup copy."""
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not db_uri.startswith("sqlite:///"):
        return jsonify({"error": "Database export only supported for SQLite"}), 400

    db_path_str = db_uri.replace("sqlite:///", "")
    # Prevent path traversal by ensuring the path is within the project root
    db_path = os.path.abspath(db_path_str)
    project_root = os.path.abspath(
        current_app.config.get("PROJECT_ROOT", "."))

    if not db_path.startswith(project_root) or not os.path.exists(db_path):
        return jsonify({"error": "Database file not found or access denied"}), 404

    # Use SQLite backup API for a consistent snapshot (avoids corruption
    # from concurrent writes during download)
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
        os.close(tmp_fd)
        source = sqlite3.connect(db_path)
        dest = sqlite3.connect(tmp_path)
        source.backup(dest)
        source.close()
        dest.close()
        return send_file(tmp_path, as_attachment=True,
                         download_name="sheepvibes.db")
    except Exception as e:
        logger.error("Database export failed: %s", e, exc_info=True)
        return jsonify({"error": "Database export failed"}), 500
