"""Blueprint for authentication endpoints."""

import logging
import re

from flask import Blueprint, jsonify, request

from ..auth import get_current_user, login_required, login_user, logout_user
from ..extensions import db
from ..models import Tab, User

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")


@auth_bp.route("/status", methods=["GET"])
def get_auth_status():
    """Returns whether initial setup is required and the current authentication state."""
    users_count = User.query.count()
    setup_required = users_count == 0
    user = get_current_user()

    return (
        jsonify(
            {
                "setup_required": setup_required,
                "authenticated": user is not None,
                "user": user.to_dict() if user else None,
            }
        ),
        200,
    )


@auth_bp.route("/setup", methods=["POST"])
def initial_setup():
    """First-run onboarding endpoint to create the master administrator account."""
    if User.query.count() > 0:
        return jsonify({"error": "Setup has already been completed"}), 403

    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    username = str(data.get("username")).strip()
    password = str(data.get("password"))
    email = str(data.get("email")).strip() if data.get("email") else None

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
        return jsonify({"error": "Password must be at least 8 characters long"}), 400

    master_admin = User(
        username=username,
        email=email,
        role="admin",
        is_active=True,
    )
    master_admin.set_password(password)

    db.session.add(master_admin)
    db.session.flush()

    # Create default tab for initial administrator
    default_tab = Tab(name="General", order=0, user_id=master_admin.id)
    db.session.add(default_tab)
    db.session.commit()

    logger.info(
        "First-run setup completed. Master administrator: %s (ID: %d)",
        username,
        master_admin.id,
    )
    login_user(master_admin)

    return (
        jsonify(
            {
                "message": "Master administrator created successfully",
                "user": master_admin.to_dict(),
            }
        ),
        201,
    )


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
        return jsonify({"error": "Incorrect current password"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long"}), 400

    user.set_password(new_password)
    db.session.commit()
    logger.info("Password changed for user: %s", user.username)

    return jsonify({"message": "Password updated successfully"}), 200
