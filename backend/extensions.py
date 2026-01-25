from apscheduler.schedulers.background import BackgroundScheduler
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
cache = Cache()
scheduler = BackgroundScheduler()
