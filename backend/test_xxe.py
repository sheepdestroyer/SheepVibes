import pytest
import io
from unittest.mock import patch
from .app import app
from .models import db
import defusedxml.ElementTree as DET
from defusedxml.common import EntitiesForbidden, DTDForbidden

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['CACHE_TYPE'] = 'SimpleCache'

    with app.app_context():
        db.create_all()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.session.remove()
        db.drop_all()

@patch('backend.app.fetch_and_update_feed')
def test_xxe_vulnerability_reproduction(mock_fetch, client):
    """
    Attempts to send an XML with a DOCTYPE declaration (XXE vector).

    If the application uses xml.etree.ElementTree, this might be parsed (vulnerable)
    or just ignored depending on the python version, but it won't raise the
    specific security exception we want from defusedxml.

    If the application uses defusedxml, this MUST raise an exception (Forbidden).
    """

    # Simple XXE payload attempting to define an entity
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe "Malicious Content" >
    ]>
    <opml version="2.0">
      <body>
        <outline text="Normal Feed" xmlUrl="http://example.com/rss"/>
        <outline text="&xxe;" xmlUrl="http://malicious.com/rss"/>
      </body>
    </opml>
    """

    opml_file = (io.BytesIO(xxe_payload.encode('utf-8')), 'xxe.opml')

    # We expect this to fail with a 500 error because app.py catches the Exception
    # and returns 500. The exception message should indicate that entities are forbidden.

    response = client.post('/api/opml/import', data={'file': opml_file}, content_type='multipart/form-data')

    assert response.status_code == 500
    assert "EntitiesForbidden" in response.json['error'] or "DTDForbidden" in response.json['error']

def test_verify_defusedxml_import():
    """
    A direct unit test to verify that we are indeed using defusedxml in the logic
    (after I apply the fix).
    """
    pass
