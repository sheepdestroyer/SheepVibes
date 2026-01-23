import os
import sys
import unittest
from io import BytesIO

# Set TESTING to true before importing app
os.environ['TESTING'] = 'true'

# Ensure we can import backend.app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import app, db

class SecurityXXETestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_entity_injection_blocked(self):
        """Test that XML Entity Injection is blocked by defusedxml."""
        # Payload with an entity definition and usage
        xxe_payload = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE opml [
  <!ENTITY xxe "malicious_content">
]>
<opml version="1.0">
    <head>
        <title>XXE Attempt</title>
    </head>
    <body>
        <outline text="&xxe;" title="XXE" type="rss" xmlUrl="http://example.com/feed" />
    </body>
</opml>
"""
        data = {
            'file': (BytesIO(xxe_payload), 'malicious.opml')
        }

        response = self.client.post('/api/opml/import', data=data, content_type='multipart/form-data')

        # Expecting 400 Bad Request due to Security Violation
        self.assertEqual(response.status_code, 400, "Should return 400 Bad Request for XML Entity Injection")
        self.assertIn('Security violation', response.get_json()['error'], "Error message should mention security violation")
        print("\nTest passed: Entity injection was correctly blocked with 400 Bad Request.")

    def test_billion_laughs_blocked(self):
        """Test that Billion Laughs DoS attack is blocked."""
        # A small version of billion laughs
        dos_payload = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<opml>
 <head><title>DoS Attempt</title></head>
 <body>
  <outline text="&lol2;" />
 </body>
</opml>
"""
        data = {
            'file': (BytesIO(dos_payload), 'dos.opml')
        }

        response = self.client.post('/api/opml/import', data=data, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 400, "Should return 400 Bad Request for Billion Laughs attack")
        self.assertIn('Security violation', response.get_json()['error'])
        print("\nTest passed: Billion Laughs attack was correctly blocked.")

if __name__ == '__main__':
    unittest.main()
