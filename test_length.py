import os

import pytest

from backend.app import app
from backend.models import Tab, db

os.environ["TESTING"] = "true"


def test_create_tab_length():
    with app.test_client() as client:
        with app.app_context():
            db.create_all()

        long_name = "A" * 150
        response = client.post("/api/tabs", json={"name": long_name})
        print(response.status_code)
        print(response.json)

        with app.app_context():
            db.drop_all()


test_create_tab_length()
