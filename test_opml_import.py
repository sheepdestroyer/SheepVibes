import requests
import os
import sys

def test_import():
    base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5001')
    url = f'{base_url}/api/opml/import'
    print(f"Testing OPML import at: {url}")

    try:
        with open('test_feeds.opml', 'rb') as f:
            files = {'file': f}
            response = requests.post(url, files=files, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")

        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        assert response.json().get('imported_count', 0) > 0, "Expected imported_count > 0"
        print("Test PASSED")

    except requests.RequestException as e:
        print(f"Request Error: {e}")
        sys.exit(1)
    except AssertionError as e:
        print(f"Assertion Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_import()
