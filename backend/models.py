import datetime
from datetime import timezone # Import timezone
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy ORM extension
# This will be initialized with the app in app.py using db.init_app(app)
db = SQLAlchemy()

# --- Database Models ---

class Tab(db.Model):
    """Represents a tab for organizing feeds."""
    __tablename__ = 'tabs'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) # Name of the tab
    order = db.Column(db.Integer, default=0) # Display order of the tab
    # Relationship to Feeds: One-to-Many (one Tab has many Feeds)
    # cascade='all, delete-orphan' means deleting a Tab also deletes its associated Feeds
    feeds = db.relationship('Feed', backref='tab', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        """Serializes the Tab object to a dictionary, including unread count."""
        # Calculate total unread count for all feeds within this tab
        total_unread = db.session.query(db.func.count(FeedItem.id)).join(Feed).filter(
            Feed.tab_id == self.id,
            FeedItem.is_read == False
        ).scalar() or 0

        return {
            'id': self.id,
            'name': self.name,
            'order': self.order,
            'unread_count': total_unread
        }

class Feed(db.Model):
    """Represents an RSS/Atom feed source."""
    __tablename__ = 'feeds'

    id = db.Column(db.Integer, primary_key=True)
    tab_id = db.Column(db.Integer, db.ForeignKey('tabs.id'), nullable=False) # Foreign key to Tab
    name = db.Column(db.String(200), nullable=False) # Name of the feed (often from feed title)
    url = db.Column(db.String(500), nullable=False) # URL of the feed
    last_updated_time = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc)) # Last time feed was successfully fetched
    # Relationship to FeedItems: One-to-Many (one Feed has many FeedItems)
    # cascade='all, delete-orphan' means deleting a Feed also deletes its associated FeedItems
    items = db.relationship('FeedItem', backref='feed', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        """Serializes the Feed object to a dictionary, including unread count."""
        # Calculate unread count for this specific feed
        unread_count = db.session.query(db.func.count(FeedItem.id)).filter(
            FeedItem.feed_id == self.id,
            FeedItem.is_read == False
        ).scalar() or 0

        return {
            'id': self.id,
            'tab_id': self.tab_id,
            'name': self.name,
            'url': self.url,
            'last_updated_time': self.last_updated_time.isoformat() if self.last_updated_time else None,
            'unread_count': unread_count
        }

class FeedItem(db.Model):
    """Represents a single item within an RSS/Atom feed."""
    __tablename__ = 'feed_items'
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(db.Integer, db.ForeignKey('feeds.id', ondelete='CASCADE'), nullable=False, index=True) # Add index
    title = db.Column(db.String, nullable=False)
    link = db.Column(db.String, nullable=False)
    published_time = db.Column(db.DateTime, nullable=True, index=True) # Add index
    fetched_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True) # Add index
    guid = db.Column(db.String, nullable=True, unique=True) # GUID should be unique

    # Define relationships (optional but helpful)
    # feed = db.relationship('Feed', back_populates='items')

    # Add a unique constraint for feed_id and link (if guid is null)?
    # Or rely on processing logic to prevent duplicates
    # __table_args__ = (db.UniqueConstraint('feed_id', 'link', name='_feed_link_uc'),)

    def to_dict(self):
        """Returns a dictionary representation of the feed item."""
        published_ts_iso = None
        if self.published_time:
            dt_published = self.published_time
            if dt_published.tzinfo is None or dt_published.tzinfo.utcoffset(dt_published) is None:
                # Naive datetime, assume UTC and make it aware
                dt_published = dt_published.replace(tzinfo=timezone.utc)
            else:
                # Aware datetime, convert to UTC
                dt_published = dt_published.astimezone(timezone.utc)
            published_ts_iso = dt_published.isoformat()

        # fetched_time is non-nullable
        dt_fetched = self.fetched_time
        if dt_fetched.tzinfo is None or dt_fetched.tzinfo.utcoffset(dt_fetched) is None:
            # Naive datetime, assume UTC and make it aware
            dt_fetched = dt_fetched.replace(tzinfo=timezone.utc)
        else:
            # Aware datetime, convert to UTC
            dt_fetched = dt_fetched.astimezone(timezone.utc)
        fetched_ts_iso = dt_fetched.isoformat()

        return {
            'id': self.id,
            'feed_id': self.feed_id,
            'title': self.title,
            'link': self.link,
            'published_time': published_ts_iso,
            'fetched_time': fetched_ts_iso,
            'is_read': self.is_read,
            'guid': self.guid
        }
