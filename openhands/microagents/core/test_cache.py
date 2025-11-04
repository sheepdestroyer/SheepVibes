import unittest
import time
from pathlib import Path
import shutil
from openhands.microagents.core.cache import MicroagentCache

class TestCache(unittest.TestCase):

    def setUp(self):
        self.cache_dir = Path("/tmp/test_cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.cache = MicroagentCache(self.cache_dir, ttl_seconds=1)

    def tearDown(self):
        shutil.rmtree(self.cache_dir)

    def test_set_and_get(self):
        self.cache.set("test_content", "test_value")
        self.assertEqual(self.cache.get("test_content"), "test_value")

    def test_ttl(self):
        self.cache.set("test_content", "test_value")
        time.sleep(1.1)
        self.assertIsNone(self.cache.get("test_content"))

    def test_invalidate(self):
        self.cache.set("test_content", "test_value")
        self.cache.invalidate("test_content")
        self.assertIsNone(self.cache.get("test_content"))

if __name__ == '__main__':
    unittest.main()
