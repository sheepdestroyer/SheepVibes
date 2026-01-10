import requests

def test_import():
    url = 'http://127.0.0.1:5001/api/opml/import'
    try:
        with open('test_feeds.opml', 'rb') as f:
            files = {'file': f}
            response = requests.post(url, files=files, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except requests.RequestException as e:
        print(f"Request Error: {e}")

if __name__ == "__main__":
    test_import()
