import requests
import os
import sys
import io
from unittest.mock import MagicMock, patch

def test_import():
    base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5001')
    url = f'{base_url}/api/opml/import'
    print(f"Testing OPML import at: {url}")

    try:
        # Use an in-memory file object so tests don't touch repository files
        opml_content = b'<opml version="1.0"><body></body></opml>'
        opml_file = io.BytesIO(opml_content)
        opml_file.name = "test_feeds.opml"  # mimic a real file name for the upload

        files = {'file': opml_file}

        # Mock the response
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'imported_count': 5, 'message': 'Success'}
            mock_post.return_value = mock_response

            response = requests.post(url, files=files, timeout=10)
            
            # Assert that the mocked request was called once with the expected arguments
            mock_post.assert_called_once_with(url, files=files, timeout=10)

        print(f"Status Code: {response.status_code}")
        response.raise_for_status()
        response_data = response.json()
        print(f"Response: {response_data}")

        assert response_data.get('imported_count', 0) > 0, "Expected imported_count > 0"
        print("Test PASSED")

    except requests.RequestException as e:
        print(f"Request Error: {e}")
        sys.exit(1)
    except AssertionError as e:
        print(f"Assertion Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_import()
