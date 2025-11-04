import hashlib
import json
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timedelta

class MicroagentCache:
    """File-based cache with TTL and deduplication"""

    def __init__(self, cache_dir: Path, ttl_seconds: int = 3600):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(seconds=ttl_seconds)
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

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
            cached = self._memory_cache[cache_key]
            cached_time = cached['timestamp']
            if datetime.now() - cached_time <= self.ttl:
                return cached['value']
            else:
                # Expired, remove from memory
                del self._memory_cache[cache_key]

        # Check file cache
        cache_path = self._get_cache_path(cache_key)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path) as f:
                cached = json.load(f)

            # Check TTL
            cached_time = datetime.fromisoformat(cached['timestamp'])
            if datetime.now() - cached_time > self.ttl:
                cache_path.unlink()  # Expired
                return None

            # Populate memory cache
            value = cached['value']
            self._memory_cache[cache_key] = {'value': value, 'timestamp': cached_time}
            return value
        except Exception:
            return None

    def set(self, content: str, value: Any) -> None:
        """Cache value with timestamp"""
        cache_key = self._get_cache_key(content)
        cache_path = self._get_cache_path(cache_key)
        now = datetime.now()

        # Update memory cache
        self._memory_cache[cache_key] = {'value': value, 'timestamp': now}

        # Update file cache
        with open(cache_path, 'w') as f:
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
