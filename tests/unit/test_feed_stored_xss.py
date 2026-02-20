import pytest
from backend.app import app, db
from backend.models import Feed, Tab

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["CACHE_TYPE"] = "SimpleCache"

    with app.app_context():
        db.create_all()
        # Create a default tab
        tab = Tab(name="Default", order=0)
        db.session.add(tab)
        db.session.commit()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.drop_all()

def test_add_feed_stored_xss_javascript_scheme(client):
    """Test that adding a feed with 'javascript:' scheme is rejected."""
    malicious_url = "javascript:alert(1)"

    response = client.post("/api/feeds", json={
        "url": malicious_url
    })

    # It SHOULD return 400 or 422, but currently it likely returns 201
    # We want to assert that it is REJECTED.
    assert response.status_code == 400
    assert "Invalid feed URL" in response.json.get("error", "")

def test_update_feed_stored_xss_javascript_scheme(client):
    """Test that updating a feed with 'javascript:' scheme is rejected."""
    # Create a valid feed first
    with app.app_context():
        tab = Tab.query.first()
        feed = Feed(name="Valid Feed", url="http://example.com/rss", tab_id=tab.id)
        db.session.add(feed)
        db.session.commit()
        feed_id = feed.id

    malicious_url = "javascript:alert(1)"

    response = client.put(f"/api/feeds/{feed_id}", json={
        "url": malicious_url
    })

    assert response.status_code == 400
    assert "Invalid feed URL" in response.json.get("error", "")
