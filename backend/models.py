import datetime
from datetime import timezone  # Import timezone

from sqlalchemy.orm import validates

# Initialize SQLAlchemy ORM extension
# This will be initialized with the app in app.py using db.init_app(app)
from .extensions import db

# --- Database Models ---


class Tab(db.Model):
    """Represents a tab for organizing feeds.

    Attributes:
        id (int): The primary key.
        name (str): The name of the tab.
        order (int): The display order of the tab.
        feeds (relationship): A relationship to the feeds in this tab.
    """

    __tablename__ = "tabs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False,
                     unique=True)  # Name of the tab
    order = db.Column(db.Integer, default=0)  # Display order of the tab
    # Relationship to Feeds: One-to-Many (one Tab has many Feeds)
    # cascade='all, delete-orphan' means deleting a Tab also deletes its associated Feeds
    feeds = db.relationship("Feed",
                            backref="tab",
                            lazy=True,
                            cascade="all, delete-orphan")

    def to_dict(self, unread_count=None):
        """Serializes the Tab object to a dictionary.

        Args:
            unread_count (int, optional): The unread count for this tab.
                                          If None, it will be queried from the DB.

        Returns:
            dict: A dictionary representation of the tab, including the unread count.
        """
        if unread_count is None:
            # Calculate total unread count for all feeds within this tab
            unread_count = (db.session.query(
                db.func.count(FeedItem.id)).join(Feed).filter(
                    Feed.tab_id == self.id,
                    FeedItem.is_read.is_(False)).scalar() or 0)

        return {
            "id": self.id,
            "name": self.name,
            "order": self.order,
            "unread_count": unread_count,
        }


class Feed(db.Model):
    """Represents an RSS/Atom feed source.

    Attributes:
        id (int): The primary key.
        tab_id (int): The foreign key for the tab this feed belongs to.
        name (str): The name of the feed.
        url (str): The URL of the feed.
        site_link (str): The URL of the feed's website.
        last_updated_time (datetime): The last time the feed was updated.
        items (relationship): A relationship to the items in this feed.
    """

    __tablename__ = "feeds"

    id = db.Column(db.Integer, primary_key=True)
    tab_id = db.Column(db.Integer, db.ForeignKey("tabs.id"),
                       nullable=False)  # Foreign key to Tab
    name = db.Column(
        db.String(200),
        nullable=False)  # Name of the feed (often from feed title)
    url = db.Column(db.String(500), nullable=False,
                    index=True)  # URL of the feed (the XML feed URL)
    site_link = db.Column(
        db.String(500),
        nullable=True)  # URL of the feed's main website (HTML link)
    last_updated_time = db.Column(
        db.DateTime, default=lambda: datetime.datetime.now(
            timezone.utc))  # Last time feed was successfully fetched
    # Relationship to FeedItems: One-to-Many (one Feed has many FeedItems)
    # cascade='all, delete-orphan' means deleting a Feed also deletes its associated FeedItems.
    # lazy='dynamic' allows for further querying on the relationship.
    items = db.relationship("FeedItem",
                            backref="feed",
                            lazy="dynamic",
                            cascade="all, delete-orphan")

    def to_dict(self, unread_count=None):
        """Serializes the Feed object to a dictionary.

        Args:
            unread_count (int, optional): The unread count for this feed.
                                          If None, it will be queried from the DB.

        Returns:
            dict: A dictionary representation of the feed, including the unread count.
        """
        if unread_count is None:
            # Calculate unread count for this specific feed
            unread_count = (db.session.query(db.func.count(
                FeedItem.id)).filter(FeedItem.feed_id == self.id,
                                     FeedItem.is_read.is_(False)).scalar()
                or 0)

        return {
            "id":
            self.id,
            "tab_id":
            self.tab_id,
            "name":
            self.name,
            "url":
            self.url,
            "site_link":
            self.site_link,
            "last_updated_time": (self.last_updated_time.isoformat()
                                  if self.last_updated_time else None),
            "unread_count":
            unread_count,
        }


class FeedItem(db.Model):
    """Represents a single item within an RSS/Atom feed.

    Attributes:
        id (int): The primary key.
        feed_id (int): The foreign key for the feed this item belongs to.
        title (str): The title of the feed item.
        link (str): The URL of the feed item.
        published_time (datetime): The time the item was published.
        fetched_time (datetime): The time the item was fetched.
        is_read (bool): Whether the item has been read.
        guid (str): The GUID of the feed item.
    """

    __tablename__ = "feed_items"
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(
        db.Integer,
        db.ForeignKey("feeds.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )  # Add index
    title = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    published_time = db.Column(db.DateTime, nullable=True,
                               index=True)  # Add index
    fetched_time = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, nullable=False, default=False,
                        index=True)  # Add index
    guid = db.Column(
        db.String, nullable=True)  # GUID unique per feed via UniqueConstraint

    __table_args__ = (
        db.UniqueConstraint("feed_id",
                            "guid",
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
        """Validates that the datetime is UTC.

        Args:
            key (str): The name of the field being validated.
            dt (datetime.datetime): The datetime object to validate.

        Returns:
            datetime.datetime: The validated datetime object.
        """
        if dt is None:
            return None
        if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
            # Aware datetime, convert to UTC and make naive for storage
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        # Naive datetime, assume it's already UTC
        return dt

    @staticmethod
    def to_iso_z_string(dt_val: datetime.datetime | None) -> str | None:
        """
        Converts a datetime object to a UTC ISO string with 'Z' suffix.
        Handles naive (assumed UTC) and timezone-aware datetime objects.
        """
        if dt_val is None:
            return None

        # At this point, dt_val from DB is naive UTC due to the validator.
        # If dt_val is directly passed (e.g. not from DB and still aware),
        # it needs conversion.
        if dt_val.tzinfo is None:
            # Naive datetime from DB (assumed UTC), make it aware UTC
            dt_val_utc = dt_val.replace(tzinfo=timezone.utc)
        else:
            # Aware datetime (e.g. passed directly, not from DB), convert to UTC
            dt_val_utc = dt_val.astimezone(timezone.utc)

        iso_string = dt_val_utc.isoformat()
        return iso_string.replace("+00:00", "Z")

    def to_dict(self):
        """Serializes the FeedItem object to a dictionary.

        Returns:
            dict: A dictionary representation of the feed item.
        """
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "title": self.title,
            "link": self.link,
            "published_time": FeedItem.to_iso_z_string(self.published_time),
            "fetched_time": FeedItem.to_iso_z_string(self.fetched_time),
            "is_read": self.is_read,
            "guid": self.guid,
        }
