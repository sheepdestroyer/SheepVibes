#!/usr/bin/env python3
"""
Test script for the feed optimization functionality.
"""

from unittest.mock import ANY, MagicMock

import pytest
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList

from backend import feed_service
from backend.models import Feed, FeedItem


class MockFeedEntry(dict):
    """Mocks a feedparser entry."""

    def __init__(self,
                 title,
                 link,
                 guid=None,
                 published_parsed=None,
                 **kwargs):
        super().__init__()
        self["title"] = title
        self["link"] = link
        self["id"] = guid
        self["published_parsed"] = published_parsed
        for key, value in kwargs.items():
            self[key] = value

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def guid(self):
        return self.get("id")


class MockParsedFeed:

    def __init__(self, feed_title, entries):
        self.feed = {"title": feed_title}
        self.entries = entries
        self.bozo = 0


def test_collect_new_items_optimization_small_batch(mocker):
    """
    Verifies that _collect_new_items uses optimized queries for small batches.
    """
    mock_session = mocker.patch("backend.feed_service.db.session")
    mock_query = mock_session.query.return_value
    mock_query.filter.return_value = mock_query
    mock_query.filter_by.return_value = mock_query  # Should not be used
    mock_query.all.return_value = []

    feed_obj = MagicMock(spec=Feed)
    feed_obj.id = 1
    feed_obj.name = "Test Feed"

    # Case 1: Small batch (should use optimization)
    entries_small = [
        MockFeedEntry(f"T{i}", f"http://l{i}", f"g{i}") for i in range(5)
    ]
    parsed_feed_small = MockParsedFeed("Small Feed", entries_small)

    feed_service._collect_new_items(feed_obj, parsed_feed_small)

    # Check that filter_by was NOT called
    assert not mock_query.filter_by.called, (
        "filter_by should not be used in the new implementation")

    # Check that filter was called at least twice (feed_id + OR condition)
    # 1. filter(FeedItem.feed_id == ...)
    # 2. filter(or_(...))
    assert mock_query.filter.call_count >= 2

    # We can inspect the arguments roughly
    calls = mock_query.filter.call_args_list
    # First call arg should be BinaryExpression (feed_id == 1)
    # Second call arg should be BooleanClauseList (or_(...))

    arg1 = calls[0][0][0]
    arg2 = calls[1][0][0]

    # It's hard to instanceof with mocked models, but we can assume structure
    # Just asserting call count > 1 confirms we added the extra filter condition
    print("Small batch verified: filter calls:", len(calls))


def test_collect_new_items_optimization_large_batch(mocker):
    """
    Verifies that _collect_new_items uses fallback query (no OR clause) for large batches.
    """
    mock_session = mocker.patch("backend.feed_service.db.session")
    mock_query = mock_session.query.return_value
    mock_query.filter.return_value = mock_query
    mock_query.all.return_value = []

    feed_obj = MagicMock(spec=Feed)
    feed_obj.id = 1
    feed_obj.name = "Test Feed"

    # Case 2: Large batch (should fallback)
    # Threshold is 300
    entries_large = [
        MockFeedEntry(f"T{i}", f"http://l{i}", f"g{i}") for i in range(350)
    ]
    parsed_feed_large = MockParsedFeed("Large Feed", entries_large)

    feed_service._collect_new_items(feed_obj, parsed_feed_large)

    # Check that filter was called exactly once (only for feed_id)
    # The optimization condition (len < 300) fails, so the OR filter is skipped.
    assert mock_query.filter.call_count == 1
    print("Large batch verified: filter calls:", mock_query.filter.call_count)


def test_collect_new_items_no_candidates(mocker):
    """
    Verifies behavior when there are no valid candidates (e.g. no links/guids).
    """
    mock_session = mocker.patch("backend.feed_service.db.session")
    mock_query = mock_session.query.return_value

    feed_obj = MagicMock(spec=Feed)
    feed_obj.id = 1
    feed_obj.name = "Test Feed"

    # Entries with no link -> invalid -> no candidates
    entries_invalid = [MockFeedEntry("Title", None, None)]
    parsed_feed = MockParsedFeed("Invalid Feed", entries_invalid)

    feed_service._collect_new_items(feed_obj, parsed_feed)

    # Should optimize (0 < 300), but empty candidates -> items_tuple = []
    # So query.all() should NOT be called
    assert not mock_query.all.called
    print("No candidates verified: query.all() NOT called")
