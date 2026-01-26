"""Tests for feed worker configuration and limit heuristics."""

import os
from unittest.mock import patch

from backend.feed_service import WORKER_FETCH_CAP, _get_max_concurrent_fetches


def test_get_max_concurrent_fetches_default():
    """Test default calculation based on cpu_count."""
    with patch("os.cpu_count", return_value=2), patch.dict(os.environ, {}, clear=True):
        # 2 * 5 = 10, capped at 20 -> 10
        assert _get_max_concurrent_fetches() == 10


def test_get_max_concurrent_fetches_default_cap():
    """Test default calculation caps at WORKER_FETCH_CAP."""
    with patch("os.cpu_count", return_value=10), patch.dict(os.environ, {}, clear=True):
        # 10 * 5 = 50, capped at 20 -> 20
        assert _get_max_concurrent_fetches() == WORKER_FETCH_CAP


def test_get_max_concurrent_fetches_explicit_below_cap():
    """Test explicit configuration below the cap."""
    with patch.dict(os.environ, {"FEED_FETCH_MAX_WORKERS": "5"}):
        assert _get_max_concurrent_fetches() == 5


def test_explicit_worker_limit_exceeds_cap():
    """Verify that an explicit environment variable exceeds the default cap."""
    with patch.dict(os.environ, {"FEED_FETCH_MAX_WORKERS": "50"}):
        # Reloading module or re-calling logic if it was cached
        # Since it's a constant in the module, we need to test the helper directly
        assert _get_max_concurrent_fetches() == 50


def test_get_max_concurrent_fetches_invalid_config():
    """Test invalid configuration falls back to default."""
    with (
        patch("os.cpu_count", return_value=1),
        patch.dict(os.environ, {"FEED_FETCH_MAX_WORKERS": "invalid"}),
    ):
        # Fallback: 1 * 5 = 5
        assert _get_max_concurrent_fetches() == 5


def test_get_max_concurrent_fetches_negative_config():
    """Test negative configuration falls back to default."""
    with (
        patch("os.cpu_count", return_value=1),
        patch.dict(os.environ, {"FEED_FETCH_MAX_WORKERS": "-5"}),
    ):
        # Fallback: 1 * 5 = 5
        assert _get_max_concurrent_fetches() == 5
