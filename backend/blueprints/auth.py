import logging
from flask import Blueprint, jsonify, request
from flask_login import login_user, logout_user, current_user, login_required
from ..extensions import db, login_manager, bcrypt
from ..models import User

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400

    username = data["username"].strip()
    password = data["password"]
    email = data.get("email", "").strip() or None

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # Check if this is the first user; if so, make them an admin
    is_admin = User.query.count() == 0

    new_user = User(username=username, password_hash=password_hash, email=email, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    logger.info("Registered new user: %s (admin: %s)", username, is_admin)
    return jsonify(new_user.to_dict()), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.check_password_hash(user.password_hash, data["password"]):
        login_user(user, remember=True)
        logger.info("User logged in: %s", user.username)
        return jsonify(user.to_dict()), 200

    return jsonify({"error": "Invalid username or password"}), 401

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info("User logged out: %s", username)
    return jsonify({"message": "Logged out successfully"}), 200

@auth_bp.route("/me", methods=["GET"])
def me():
    if current_user.is_authenticated:
        return jsonify(current_user.to_dict()), 200
    return jsonify({"error": "Not authenticated"}), 401
