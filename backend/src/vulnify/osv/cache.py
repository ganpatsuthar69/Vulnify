"""In-memory cache for OSV query responses with configurable TTL and entry expiration."""

from dataclasses import dataclass
import time
from typing import Any

from vulnify.osv.models import OsvVulnerability


@dataclass
class _CacheEntry:
    vulnerabilities: list[OsvVulnerability]
    cached_at: float
    ttl_seconds: int

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.cached_at) > self.ttl_seconds


class OsvCache:
    """Thread-safe and async-safe in-memory cache for OSV package version lookups."""

    def __init__(self, default_ttl_seconds: int = 86400) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._store: dict[str, _CacheEntry] = {}

    def _build_key(self, ecosystem: str, name: str, version: str) -> str:
        return f"{ecosystem.strip().lower()}:{name.strip().lower()}:{version.strip()}"

    def get(self, ecosystem: str, name: str, version: str) -> list[OsvVulnerability] | None:
        """Retrieve cached vulnerabilities if present and unexpired.
        
        Returns None on cache miss or expired entry.
        Returns an empty list `[]` for cached confirmed no-match results.
        """
        key = self._build_key(ecosystem, name, version)
        entry = self._store.get(key)
        if entry is None:
            return None

        if entry.is_expired:
            # Evict expired entry
            del self._store[key]
            return None

        return list(entry.vulnerabilities)

    def set(
        self,
        ecosystem: str,
        name: str,
        version: str,
        vulnerabilities: list[OsvVulnerability],
        ttl_seconds: int | None = None,
    ) -> None:
        """Store lookup result in cache.
        
        Both positive matches and legitimate no-match results are cached.
        Transient errors must never be passed here.
        """
        key = self._build_key(ecosystem, name, version)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        self._store[key] = _CacheEntry(
            vulnerabilities=list(vulnerabilities),
            cached_at=time.time(),
            ttl_seconds=ttl,
        )

    def clear(self) -> None:
        """Clear all entries from cache."""
        self._store.clear()

    def size(self) -> int:
        """Return total active entries in cache."""
        # Evict expired on count
        now = time.time()
        expired_keys = [k for k, v in self._store.items() if (now - v.cached_at) > v.ttl_seconds]
        for k in expired_keys:
            del self._store[k]
        return len(self._store)


# Global singleton cache instance
_global_osv_cache: OsvCache | None = None


def get_osv_cache(ttl_seconds: int | None = None) -> OsvCache:
    global _global_osv_cache
    if _global_osv_cache is None:
        from vulnify.config import get_settings

        effective_ttl = (
            ttl_seconds if ttl_seconds is not None else get_settings().OSV_CACHE_TTL_SECONDS
        )
        _global_osv_cache = OsvCache(default_ttl_seconds=effective_ttl)
    return _global_osv_cache

