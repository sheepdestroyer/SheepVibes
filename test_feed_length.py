import pytest
import os

os.environ["TESTING"] = "true"

from backend.app import app
from backend.models import db, Feed, Tab

def test_add_feed_length():
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            db.session.add(Tab(name="default"))
            db.session.commit()

        long_url = "http://example.com/" + "A" * 500
        response = client.post("/api/feeds", json={"url": long_url})
        print("add feed long url status:", response.status_code)

        with app.app_context():
            db.drop_all()

test_add_feed_length()
