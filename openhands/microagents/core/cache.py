import hashlib
import json
import logging
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timedelta, timezone
from collections import OrderedDict

logger = logging.getLogger(__name__)

class MicroagentCache:
    """File-based cache with TTL and deduplication"""

    def __init__(self, cache_dir: Path, ttl_seconds: int = 3600, max_size: int = 128):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_size = max_size
        self._memory_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def _get_cache_key(self, content: str) -> str:
        """Generate deterministic cache key"""
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_cache_path(self, cache_key: str) -> Path:
        return self.cache_dir / f"{cache_key}.json"

    def get(self, content: str) -> Optional[Any]:
        """Get cached value if valid"""
        cache_key = self._get_cache_key(content)

        # Check memory cache first
        if cache_key in self._memory_cache:
            self._memory_cache.move_to_end(cache_key)
            cached = self._memory_cache[cache_key]
            cached_time = cached['timestamp']
            if datetime.now(timezone.utc) - cached_time <= self.ttl:
                return cached['value']
            else:
                # Expired, remove from memory
                del self._memory_cache[cache_key]

        # Check file cache
        cache_path = self._get_cache_path(cache_key)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path, encoding="utf-8") as f:
                cached = json.load(f)

            cached_time = datetime.fromisoformat(cached['timestamp'])
            if datetime.now(timezone.utc) - cached_time > self.ttl:
                try:
                    cache_path.unlink()  # Expired
                except OSError as e:
                    logger.warning(f"Failed to remove expired cache file {cache_path}: {e}")
                return None

            value = cached['value']
            self._memory_cache[cache_key] = {'value': value, 'timestamp': cached_time}
            return value
        except FileNotFoundError:
            return None  # File not found is a normal cache miss
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Cache corruption detected in {cache_path}: {e}")
            try:
                cache_path.unlink()  # Attempt to remove corrupted file
            except OSError as unlink_error:
                logger.error(f"Failed to remove corrupted cache file {cache_path}: {unlink_error}")
            return None

    def set(self, content: str, value: Any) -> None:
        """Cache value with timestamp"""
        cache_key = self._get_cache_key(content)
        cache_path = self._get_cache_path(cache_key)
        now = datetime.now(timezone.utc)

        # Update memory cache
        self._memory_cache[cache_key] = {'value': value, 'timestamp': now}
        self._memory_cache.move_to_end(cache_key)
        if len(self._memory_cache) > self.max_size:
            self._memory_cache.popitem(last=False)

        # Update file cache
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': now.isoformat(),
                'value': value
            }, f)

    def invalidate(self, content: str) -> None:
        """Invalidate specific cache entry"""
        cache_key = self._get_cache_key(content)
        self._memory_cache.pop(cache_key, None)
        cache_path = self._get_cache_path(cache_key)
        if cache_path.exists():
            cache_path.unlink()

    def clear_all(self) -> None:
        """Clear entire cache"""
        self._memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
