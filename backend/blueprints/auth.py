"""Blueprint for authentication endpoints."""

import logging

from flask import Blueprint, jsonify, request

from ..auth import get_current_user, login_required, login_user, logout_user
from ..extensions import db
from ..models import User

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticates user credentials and creates a session."""
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400

    username = str(data.get("username")).strip()
    password = str(data.get("password"))

    user = User.query.filter(db.func.lower(User.username) == username.lower()).first()

    if not user or not user.check_password(password):
        logger.warning("Failed login attempt for username: %s", username)
        return jsonify({"error": "Invalid username or password"}), 401

    if not user.is_active:
        logger.warning("Login attempted for deactivated account: %s", username)
        return jsonify({"error": "Account is deactivated"}), 403

    login_user(user)
    return jsonify({"message": "Login successful", "user": user.to_dict()}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logs out the current user and clears session."""
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/me", methods=["GET"])
def get_current_session_user():
    """Returns the current authenticated user or unauthenticated state."""
    user = get_current_user()
    if user:
        return jsonify({"authenticated": True, "user": user.to_dict()}), 200
    return jsonify({"authenticated": False, "user": None}), 200


@auth_bp.route("/password", methods=["PUT", "POST"])
@login_required
def change_password():
    """Changes the password of the currently authenticated user."""
    user = get_current_user()
    data = request.get_json()
    if not data or not data.get("current_password") or not data.get("new_password"):
        return jsonify({"error": "Missing current_password or new_password"}), 400

    current_password = str(data.get("current_password"))
    new_password = str(data.get("new_password"))

    if not user.check_password(current_password):
        return jsonify({"error": "Incorrect current password"}), 401

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long"}), 400

    user.set_password(new_password)
    db.session.commit()
    logger.info("Password changed for user: %s", user.username)

    return jsonify({"message": "Password updated successfully"}), 200
