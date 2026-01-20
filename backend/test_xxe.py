import pytest
import io
import defusedxml.ElementTree as SafeET
import xml.etree.ElementTree as ET
from defusedxml.common import DefusedXmlException, EntitiesForbidden

from .app import app, db
from .models import Tab

@pytest.fixture
def client():
    """Configures the Flask app for testing and provides a test client."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['CACHE_TYPE'] = 'SimpleCache'

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()

def test_xxe_vulnerability_mitigated(client):
    """
    Attempts to exploit XXE by uploading a malicious OPML file.
    The expected behavior is that defusedxml will raise an error,
    which the application handles by returning a 500 or 400 error.
    """
    xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><opml version="2.0">
      <body>
        <outline text="&xxe;" xmlUrl="http://example.com/rss"/>
      </body>
    </opml>"""

    opml_file = (io.BytesIO(xxe_payload.encode('utf-8')), 'xxe_attack.opml')

    with app.app_context():
        tab = Tab(name="Target Tab", order=0)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    response = client.post('/api/opml/import', data={'file': opml_file, 'tab_id': str(tab_id)}, content_type='multipart/form-data')

    # The application catches general exceptions and returns 500 with the error message.
    # We verify that the import did NOT succeed (status code is not 200)
    # and that the error indicates a security failure or XML parsing issue.
    assert response.status_code in [400, 500]
    assert 'error' in response.json

    # Defusedxml typically raises EntitiesForbidden when DTD entities are present.
    # The app logs the exception but returns a generic 500 error message 'Error processing OPML file: ...'
    # Check that we didn't get a success message.
    assert 'imported_count' not in response.json

def test_xxe_exploit_fails_with_defusedxml():
    """
    Directly tests that defusedxml raises an error for the payload,
    confirming it blocks the attack pattern.
    """
    xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><opml version="2.0">
      <body>
        <outline text="&xxe;" xmlUrl="http://example.com/rss"/>
      </body>
    </opml>"""

    try:
        SafeET.fromstring(xxe_payload)
        pytest.fail("defusedxml should have raised an exception for XXE payload")
    except (DefusedXmlException, EntitiesForbidden):
        pass # Success: attack blocked
    except Exception as e:
        pytest.fail(f"Unexpected exception type: {type(e)}")

def test_standard_et_is_vulnerable():
    """
    Demonstrate that standard ElementTree tries to parse it.
    """
    xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///dev/null" >]><opml version="2.0">
      <body>
        <outline text="&xxe;" xmlUrl="http://example.com/rss"/>
      </body>
    </opml>"""

    try:
        # Standard ET parses it (might fail on entity resolution depending on version/config, but doesn't forbid DTD)
        ET.fromstring(xxe_payload)
    except Exception as e:
        # It might fail for other reasons, but not DefusedXmlException
        assert "DefusedXmlException" not in str(type(e))
