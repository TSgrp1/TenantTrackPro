"""Simple in-memory cache for frequently accessed data"""
import time
from typing import Any, Optional

class CacheManager:
    def __init__(self):
        self._cache = {}
        self._timestamps = {}
        
    def get(self, key: str, ttl: int = 300) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self._cache:
            if time.time() - self._timestamps[key] < ttl:
                return self._cache[key]
            else:
                # Expired, remove
                del self._cache[key]
                del self._timestamps[key]
        return None
    
    def set(self, key: str, value: Any):
        """Set cached value"""
        self._cache[key] = value
        self._timestamps[key] = time.time()
    
    def invalidate(self, pattern: str = None):
        """Invalidate cache entries"""
        if pattern:
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self._cache[key]
                del self._timestamps[key]
        else:
            self._cache.clear()
            self._timestamps.clear()

# Global cache instance
cache = CacheManager()