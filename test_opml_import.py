import requests

def test_import():
    url = 'http://127.0.0.1:5001/api/opml/import'
    files = {'file': open('test_feeds.opml', 'rb')}
    try:
        response = requests.post(url, files=files)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_import()
