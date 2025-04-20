import os
import logging
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sheepvibes')

# Initialize Flask app
app = Flask(__name__)

# Configure SQLite database
db_path = os.environ.get('DATABASE_PATH', os.path.join(os.path.abspath(os.path.dirname(__file__)), 'sheepvibes.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define database models
class Tab(db.Model):
    __tablename__ = 'tabs'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    order = db.Column(db.Integer, default=0)
    feeds = db.relationship('Feed', backref='tab', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'order': self.order
        }

class Feed(db.Model):
    __tablename__ = 'feeds'
    
    id = db.Column(db.Integer, primary_key=True)
    tab_id = db.Column(db.Integer, db.ForeignKey('tabs.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    last_updated_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    items = db.relationship('FeedItem', backref='feed', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'tab_id': self.tab_id,
            'name': self.name,
            'url': self.url,
            'last_updated_time': self.last_updated_time.isoformat() if self.last_updated_time else None
        }

class FeedItem(db.Model):
    __tablename__ = 'feed_items'
    
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(db.Integer, db.ForeignKey('feeds.id'), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(500), nullable=False)
    published_time = db.Column(db.DateTime)
    fetched_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    guid = db.Column(db.String(500), nullable=True, unique=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'feed_id': self.feed_id,
            'title': self.title,
            'link': self.link,
            'published_time': self.published_time.isoformat() if self.published_time else None,
            'fetched_time': self.fetched_time.isoformat() if self.fetched_time else None,
            'is_read': self.is_read
        }

# Database initialization function
def init_db():
    with app.app_context():
        # Create all tables if they don't exist
        db.create_all()
        
        # Create a default tab if none exists
        if not Tab.query.first():
            default_tab = Tab(name="Home", order=0)
            db.session.add(default_tab)
            db.session.commit()
            logger.info("Created default 'Home' tab")

# Initialize scheduler for background tasks (will be used in Phase 1)
scheduler = BackgroundScheduler()

# Basic route for testing
@app.route('/')
def index():
    return jsonify({'status': 'SheepVibes API is running'})

# Initialize and start the application
if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Start the scheduler
    scheduler.start()
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
    
    logger.info("SheepVibes application started")
