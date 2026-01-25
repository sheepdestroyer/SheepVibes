import os
import xml.etree.ElementTree as ET

import pytest

from .app import app, db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["CACHE_TYPE"] = "SimpleCache"

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_xxe_blocked(client):
    """
    Test that the application blocks XXE attacks using defusedxml.
    """
    secret_file = os.path.abspath("secret.txt")

    opml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE opml [
      <!ENTITY xxe SYSTEM "file://{secret_file}">
    ]>
    <opml version="2.0">
      <head>
        <title>&xxe;</title>
      </head>
      <body>
      </body>
    </opml>
    """

    import io

    opml_file = (io.BytesIO(opml_content.encode("utf-8")), "xxe.opml")

    response = client.post(
        "/api/opml/import", data={"file": opml_file}, content_type="multipart/form-data"
    )

    # Assert 400 Bad Request
    assert response.status_code == 400
    # Assert error message indicates rejected entity
    error_msg = response.json.get("error", "")
    print(f"XXE Blocked Error: {error_msg}")
    assert (
        "EntitiesForbidden" in error_msg
        or "undefined entity" in error_msg
        or "unsafe" in error_msg
    )


def test_billion_laughs_blocked(client):
    """
    Test that the application blocks Billion Laughs DoS attacks.
    """
    payload = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <opml>
        <head><title>&lol3;</title></head>
        <body></body>
    </opml>
    """

    import io

    opml_file = (io.BytesIO(payload.encode("utf-8")), "dos.opml")

    response = client.post(
        "/api/opml/import", data={"file": opml_file}, content_type="multipart/form-data"
    )

    # Assert 400 Bad Request
    assert response.status_code == 400
    error_msg = response.json.get("error", "")
    print(f"Billion Laughs Blocked Error: {error_msg}")
    assert "EntitiesForbidden" in error_msg or "unsafe" in error_msg


if __name__ == "__main__":
    pass
