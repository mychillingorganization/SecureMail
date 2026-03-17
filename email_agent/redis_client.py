import json
import redis
from typing import Optional, Dict, Any, List


class RedisWhitelistCache:
    """
    O(1) domain whitelist lookup backed by Redis.

    Features:
    - TTL: 24 hours by default (configurable)
    - Connection pooling: max 10 connections
    - Bulk-add via Redis pipeline
    - In-memory hit/miss metrics
    """

    DEFAULT_TTL = 86400  # 24 hours in seconds

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        max_connections: int = 10,
        ttl: int = DEFAULT_TTL,
    ):
        self.ttl = ttl
        self._pool = redis.ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=True,
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # In-memory counters for cache metrics
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def is_whitelisted(self, domain: str) -> bool:
        """
        Check whether a domain is in the whitelist.
        O(1) lookup via Redis EXISTS → True if whitelisted.
        """
        key = self._key(domain)
        result = self._client.exists(key)

        if result:
            self._hits += 1
        else:
            self._misses += 1

        return bool(result)

    def add(self, domain: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a domain to the whitelist.
        Optionally stores metadata (e.g. {"reason": "internal"}). Expires after TTL.
        """
        key = self._key(domain)
        value = json.dumps(metadata) if metadata else "1"
        self._client.setex(key, self.ttl, value)

    def remove(self, domain: str) -> bool:
        """Remove a domain from the whitelist. Returns True if it was present."""
        return bool(self._client.delete(self._key(domain)))

    def bulk_add(self, domains: List[str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add multiple domains efficiently using a Redis pipeline."""
        value = json.dumps(metadata) if metadata else "1"
        pipe = self._client.pipeline()
        for domain in domains:
            pipe.setex(self._key(domain), self.ttl, value)
        pipe.execute()

    def get_metadata(self, domain: str) -> Optional[Dict[str, Any]]:
        """Return stored metadata for a whitelisted domain, or None."""
        raw = self._client.get(self._key(domain))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {"value": raw}

    # ------------------------------------------------------------------ #
    # Metrics
    # ------------------------------------------------------------------ #

    def get_metrics(self) -> Dict[str, Any]:
        """Return cache hit/miss statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0.0
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total": total,
            "hit_rate_pct": round(hit_rate, 2),
        }

    def reset_metrics(self) -> None:
        """Reset hit/miss counters."""
        self._hits = 0
        self._misses = 0

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    def ping(self) -> bool:
        """Return True if the Redis connection is alive."""
        try:
            return self._client.ping()
        except redis.ConnectionError:
            return False

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _key(self, domain: str) -> str:
        return f"whitelist:{domain.lower().strip()}"
