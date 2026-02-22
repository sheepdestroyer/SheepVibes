import datetime
from datetime import timezone

from flask_login import UserMixin
from sqlalchemy.orm import validates

from .extensions import db


class User(db.Model, UserMixin):
    """Represents a user of the application."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )

    # Relationships
    tabs = db.relationship(
        "Tab", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    subscriptions = db.relationship(
        "Subscription", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    item_states = db.relationship(
        "UserItemState", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Tab(db.Model):
    """Represents a tab for organizing feeds."""

    __tablename__ = "tabs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)

    # Relationship to Subscriptions: One-to-Many
    subscriptions = db.relationship(
        "Subscription", backref="tab", lazy=True, cascade="all, delete-orphan"
    )

    __table_args__ = (
        db.UniqueConstraint("user_id", "name", name="uq_tab_user_id_name"),
    )

    def to_dict(self, unread_count=None):
        if unread_count is None:
            # Calculate total unread count for all subscriptions within this tab
            # This is slow, better to use joined queries in blueprints
            unread_count = (
                db.session.query(db.func.count(FeedItem.id))
                .join(Feed, Feed.id == FeedItem.feed_id)
                .join(Subscription, Subscription.feed_id == Feed.id)
                .outerjoin(
                    UserItemState,
                    db.and_(
                        UserItemState.item_id == FeedItem.id,
                        UserItemState.user_id == self.user_id,
                    ),
                )
                .filter(
                    Subscription.tab_id == self.id,
                    db.or_(
                        UserItemState.is_read.is_(False),
                        UserItemState.is_read.is_(None),
                    ),
                )
                .scalar()
                or 0
            )

        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "order": self.order,
            "unread_count": unread_count,
        }


class Feed(db.Model):
    """Represents a global RSS/Atom feed source."""

    __tablename__ = "feeds"

    id = db.Column(db.Integer, primary_key=True)
    # Default name from feed title
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False, unique=True)
    site_link = db.Column(db.String(500), nullable=True)
    last_updated_time = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )

    items = db.relationship(
        "FeedItem", backref="feed", lazy="dynamic", cascade="all, delete-orphan"
    )
    subscriptions = db.relationship(
        "Subscription", backref="feed", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self, unread_count=0):
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "site_link": self.site_link,
            "last_updated_time": (
                self.last_updated_time.isoformat() if self.last_updated_time else None
            ),
            "unread_count": unread_count,
        }


class Subscription(db.Model):
    """Links a User to a Feed within a Tab."""

    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tab_id = db.Column(db.Integer, db.ForeignKey("tabs.id"), nullable=False)
    feed_id = db.Column(db.Integer, db.ForeignKey("feeds.id"), nullable=False)
    # User's alias for the feed
    custom_name = db.Column(db.String(200), nullable=True)
    order = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "feed_id", name="uq_subscription_user_id_feed_id"
        ),
    )

    def to_dict(self, unread_count=0):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "tab_id": self.tab_id,
            "feed_id": self.feed_id,
            "name": self.custom_name or self.feed.name,
            "url": self.feed.url,
            "site_link": self.feed.site_link,
            "last_updated_time": (
                self.feed.last_updated_time.isoformat()
                if self.feed.last_updated_time
                else None
            ),
            "unread_count": unread_count,
        }


class FeedItem(db.Model):
    """Represents a single item within a global Feed."""

    __tablename__ = "feed_items"
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(
        db.Integer,
        db.ForeignKey("feeds.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    published_time = db.Column(db.DateTime, nullable=True, index=True)
    fetched_time = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.datetime.now(timezone.utc)
    )
    guid = db.Column(db.String, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("feed_id", "guid",
                            name="uq_feed_item_feed_id_guid"),
        db.Index(
            "ix_feed_items_feed_id_published_fetched_time",
            "feed_id",
            "published_time",
            "fetched_time",
        ),
    )

    @validates("published_time", "fetched_time")
    def validate_datetime_utc(self, key, dt):
        if dt is None:
            return None
        if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    @staticmethod
    def to_iso_z_string(dt_val: datetime.datetime | None) -> str | None:
        if dt_val is None:
            return None
        if dt_val.tzinfo is None:
            dt_val_utc = dt_val.replace(tzinfo=timezone.utc)
        else:
            dt_val_utc = dt_val.astimezone(timezone.utc)
        return dt_val_utc.isoformat().replace("+00:00", "Z")

    def to_dict(self, is_read=False):
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "title": self.title,
            "link": self.link,
            "published_time": FeedItem.to_iso_z_string(self.published_time),
            "fetched_time": FeedItem.to_iso_z_string(self.fetched_time),
            "is_read": is_read,
            "guid": self.guid,
        }


class UserItemState(db.Model):
    """Tracks per-user state for a FeedItem (e.g., is_read)."""

    __tablename__ = "user_item_states"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    item_id = db.Column(
        db.Integer, db.ForeignKey("feed_items.id", ondelete="CASCADE"), nullable=False
    )
    is_read = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "user_id", "item_id", name="uq_user_item_state_user_id_item_id"
        ),
        db.Index("ix_user_item_states_user_id_is_read", "user_id", "is_read"),
    )
