import pytest
import io
from backend.app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_xxe_protection(client):
    """
    Tests that the XML parser rejects DTDs, which is a sign of using defusedxml.
    Standard ElementTree allows DOCTYPE declarations if they aren't expanded,
    which leaves the door open for attacks if the parser config changes or if specific python versions are used.
    defusedxml should block the DOCTYPE entirely.
    """
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE opml [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <opml version="2.0">
        <head>
            <title>XXE Test</title>
        </head>
        <body>
            <outline text="Normal" />
        </body>
    </opml>
    """

    data = {
        'file': (io.BytesIO(xxe_payload.encode('utf-8')), 'xxe.opml')
    }

    response = client.post('/api/opml/import', data=data, content_type='multipart/form-data')

    # We expect defusedxml to raise an error (DTDForbidden), which we should catch and return as 400.
    # Current implementation returns 200 because it ignores the DOCTYPE.

    print(f"\nResponse status: {response.status_code}")
    print(f"Response data: {response.get_json()}")

    assert response.status_code == 400, "Should reject XML with DTD/DOCTYPE"
    error_msg = response.get_json().get('error', '')
    assert "DTDForbidden" in error_msg or "EntitiesForbidden" in error_msg or "Malformed OPML file" in error_msg
