import pytest
import io
from .app import app
from .models import db, Tab, Feed

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['CACHE_TYPE'] = 'SimpleCache'

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()

def test_internal_entity_expansion_blocked(client):
    """
    Checks that internal entity expansion is BLOCKED by defusedxml.
    """
    # Create a tab to import into
    with app.app_context():
        tab = Tab(name="Target Tab", order=0)
        db.session.add(tab)
        db.session.commit()
        tab_id = tab.id

    # Payload with internal entity
    opml_content = """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY test "ExpandedEntity">
]>
<opml version="1.0">
  <body>
    <outline text="&test;" xmlUrl="http://example.com/rss"/>
  </body>
</opml>
"""
    opml_file = (io.BytesIO(opml_content.encode('utf-8')), 'entity.opml')

    # Send the request
    response = client.post('/api/opml/import',
                          data={'file': opml_file, 'tab_id': str(tab_id)},
                          content_type='multipart/form-data')

    # Status should be 400 because defusedxml raises a security exception which we now catch
    assert response.status_code == 400
    assert "Security violation detected" in response.json['error']

    with app.app_context():
        # Verify no feed was created
        feed = Feed.query.filter_by(tab_id=tab_id).first()
        assert feed is None, "Feed should not be created if XML parsing failed."
