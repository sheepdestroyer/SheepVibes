import io

import pytest

from backend.app import app


def test_opml_import_txt_disallowed(client):
    """Test that .txt is now disallowed."""
    url = "/api/opml/import"

    data_txt = {"file": (io.BytesIO(b"dummy"), "test.txt")}
    response = client.post(url,
                           data=data_txt,
                           content_type="multipart/form-data")
    assert response.status_code == 400
    assert "Invalid file type" in response.get_json()["error"]


def test_opml_import_allowed_extensions(client, mocker):
    """Test that .opml and .xml are allowed."""
    url = "/api/opml/import"
    mocker.patch(
        "backend.blueprints.opml.import_opml_service",
        return_value=({
            "imported_count": 0
        }, None),
    )

    for ext in [".opml", ".xml"]:
        data = {"file": (io.BytesIO(b"<opml></opml>"), f"test{ext}")}
        response = client.post(url,
                               data=data,
                               content_type="multipart/form-data")
        assert response.status_code == 200


def test_opml_import_disallowed_extension(client):
    """Test that other extensions are disallowed."""
    url = "/api/opml/import"
    data = {"file": (io.BytesIO(b"dummy"), "test.exe")}
    response = client.post(url, data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert "Invalid file type" in response.get_json()["error"]
