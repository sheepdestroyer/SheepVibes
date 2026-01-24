import pytest
import io
import os

# Set testing environment variable
os.environ['TESTING'] = 'true'

from backend.app import app, db
from backend.models import Feed

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_xxe_prevention(client):
    # Payload with internal entity
    xxe_payload = """<?xml version="1.0"?>
    <!DOCTYPE opml [
    <!ENTITY xxe "VULNERABLE">
    ]>
    <opml version="2.0">
        <body>
            <outline text="&xxe;" xmlUrl="http://example.com/rss"/>
        </body>
    </opml>
    """

    data = {
        'file': (io.BytesIO(xxe_payload.encode('utf-8')), 'xxe.opml')
    }

    # defusedxml raises an exception when it encounters DTDs/Entities.
    # Our app catches it and returns 400 with "Security violation"
    response = client.post('/api/opml/import', data=data, content_type='multipart/form-data')

    assert response.status_code == 400
    assert "Security violation" in response.get_json()['error']

    # Verify no feed was added
    with app.app_context():
        feed = Feed.query.filter_by(url="http://example.com/rss").first()
        assert feed is None
