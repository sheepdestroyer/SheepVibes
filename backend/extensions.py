from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
cache = Cache()
scheduler = BackgroundScheduler()
