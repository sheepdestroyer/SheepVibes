"""Authentication and authorization utilities for SheepVibes."""

from __future__ import annotations

import datetime
from datetime import timezone
from functools import wraps
import logging

from flask import g, jsonify, request, session

from .extensions import db
from .models import User

logger = logging.getLogger(__name__)


def get_current_user() -> User | None:
    """Retrieves the currently authenticated user from session or cache.

    Returns:
        User | None: The authenticated User object, or None if unauthenticated.
    """
    if hasattr(g, "_current_user"):
        return g._current_user

    user_id = session.get("user_id")
    if not user_id:
        g._current_user = None
        return None

    user = db.session.get(User, user_id)
    if not user or not user.is_active:
        session.clear()
        g._current_user = None
        return None

    g._current_user = user
    return user


def login_user(user: User) -> None:
    """Authenticates a user and establishes their session.

    Args:
        user (User): The user object to log in.
    """
    session["user_id"] = user.id
    session.permanent = True
    user.last_login_at = datetime.datetime.now(timezone.utc)
    db.session.commit()
    g._current_user = user
    logger.info("User logged in: %s (ID: %s)", user.username, user.id)


def logout_user() -> None:
    """Terminates the current user session."""
    user = get_current_user()
    if user:
        logger.info("User logged out: %s (ID: %s)", user.username, user.id)
    session.clear()
    g._current_user = None


def login_required(f):
    """Decorator requiring an authenticated active user for route access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator requiring an authenticated administrator for route access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        if not user.is_admin:
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function
