import logging
import os
from functools import wraps
from flask import Blueprint, jsonify, current_app, send_file
from flask_login import login_required, current_user
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

    db.session.delete(user)
    db.session.commit()
    logger.info("Admin %s deleted user %s", current_user.username, user.username)
    return jsonify({"message": f"User {user.username} deleted"}), 200

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
    logger.info("Admin %s toggled admin status for user %s to %s",
                current_user.username, user.username, user.is_admin)
    return jsonify(user.to_dict()), 200

@admin_bp.route("/export-db", methods=["GET"])
@login_required
@admin_required
def export_db():
    db_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not db_uri.startswith("sqlite:///"):
        return jsonify({"error": "Database export only supported for SQLite"}), 400

    db_path = db_uri.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return jsonify({"error": "Database file not found"}), 404

    return send_file(db_path, as_attachment=True)
