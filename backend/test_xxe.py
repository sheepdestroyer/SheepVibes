
import pytest
import io
from .app import app, db, Tab

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['CACHE_TYPE'] = 'SimpleCache'

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()

def test_import_opml_xxe_protection(client):
    """Test that OPML import blocks XML External Entity (XXE) attacks."""

    # XXE Payload: tries to access /etc/passwd
    xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><opml version="2.0">
      <body>
        <outline text="&xxe;" />
      </body>
    </opml>"""

    opml_file = (io.BytesIO(xxe_payload.encode('utf-8')), 'xxe.opml')

    # We need a tab to import into, though failure should happen at parse time
    with app.app_context():
        tab = Tab(name="Target Tab")
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    response = client.post(
        '/api/opml/import',
        data={'file': opml_file, 'tab_id': str(tab_id)},
        content_type='multipart/form-data'
    )

    # We expect a 500 error because defusedxml raises an exception that is caught by the generic Exception handler
    # Or a 400 if it's caught as malformed.
    # But specifically, we want to ensure it didn't succeed (200) or leak data.

    # If it was vulnerable, it might return 200 and try to fetch "root:x:0:0..." as a feed URL or name.

    # Assert failure
    assert response.status_code in [400, 500]

    # Check that the error message indicates a security blocking or parsing error
    # defusedxml raises EntitiesForbidden
    assert 'error' in response.json
    # The error message from app.py: "Error processing OPML file: EntitiesForbidden(...)"
    assert 'EntitiesForbidden' in response.json['error'] or 'DTDForbidden' in response.json['error']

def test_import_opml_billion_laughs_protection(client):
    """Test that OPML import blocks Billion Laughs attack (DoS)."""

    billion_laughs = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ELEMENT lolz (#PCDATA)>
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
     <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
     <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
     <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
     <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <opml><body><outline text="&lol9;" /></body></opml>"""

    opml_file = (io.BytesIO(billion_laughs.encode('utf-8')), 'dos.opml')

    with app.app_context():
        tab = Tab(name="Target Tab")
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    response = client.post(
        '/api/opml/import',
        data={'file': opml_file, 'tab_id': str(tab_id)},
        content_type='multipart/form-data'
    )

    assert response.status_code in [400, 500]
    assert 'error' in response.json
    # defusedxml also blocks this
    assert 'EntitiesForbidden' in response.json['error'] or 'DTDForbidden' in response.json['error']
