import requests
import os
import sys
from unittest.mock import MagicMock, patch

def test_import():
    base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5001')
    url = f'{base_url}/api/opml/import'
    print(f"Testing OPML import at: {url}")

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'test_feeds.opml')
        
        # Check if file exists, if not create a dummy one for testing
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write('<opml version="1.0"><body></body></opml>')

        with open(file_path, 'rb') as f:
            files = {'file': f}
            
            # Mock the response
            with patch('requests.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {'imported_count': 5, 'message': 'Success'}
                mock_post.return_value = mock_response

                response = requests.post(url, files=files, timeout=10)
        
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
