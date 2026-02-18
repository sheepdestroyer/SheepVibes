import datetime
import unittest
from datetime import timezone

from backend.models import FeedItem


class TestFeedItemSerialization(unittest.TestCase):

    def test_to_iso_z_string_naive(self):
        # Naive datetime (simulating DB retrieval)
        naive_dt = datetime.datetime(2023, 1, 1, 12, 0, 0)
        expected = "2023-01-01T12:00:00Z"
        result = FeedItem.to_iso_z_string(naive_dt)
        self.assertEqual(result, expected)

    def test_to_iso_z_string_aware_utc(self):
        # Aware datetime in UTC
        aware_dt = datetime.datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expected = "2023-01-01T12:00:00Z"
        result = FeedItem.to_iso_z_string(aware_dt)
        self.assertEqual(result, expected)

    def test_to_iso_z_string_aware_other_tz(self):
        # Aware datetime in non-UTC (e.g. UTC+1)
        tz = datetime.timezone(datetime.timedelta(hours=1))
        aware_dt = datetime.datetime(2023, 1, 1, 13, 0, 0, tzinfo=tz)
        # 13:00 UTC+1 is 12:00 UTC
        expected = "2023-01-01T12:00:00Z"
        result = FeedItem.to_iso_z_string(aware_dt)
        self.assertEqual(result, expected)

    def test_to_iso_z_string_none(self):
        result = FeedItem.to_iso_z_string(None)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
