"""
Enhanced Redis client with 3-keyspace management:
1. Cache layer for file analysis results (7-day TTL)
2. Whitelist/Threat cache (24h TTL)
3. Pipeline session store (1h TTL)
"""

import json
from datetime import datetime
from typing import Any, Optional
import redis
from redis.connection import ConnectionPool


class EnhancedRedisClient:
    """
    Multi-keyspace Redis manager supporting:
    - File analysis cache (7 days)
    - Whitelist/threat cache (24 hours)
    - Pipeline session store (1 hour)
    """

    # TTL constants (in seconds)
    TTL_FILE_ANALYSIS = 7 * 24 * 3600      # 7 days
    TTL_WHITELIST = 24 * 3600               # 24 hours
    TTL_PIPELINE_SESSION = 1 * 3600         # 1 hour

    # Keyspace prefixes
    PREFIX_FILE_ANALYSIS = "file:analysis"
    PREFIX_WHITELIST = "whitelist"
    PREFIX_THREAT = "threat"
    PREFIX_PIPELINE_SESSION = "pipeline:session"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        max_connections: int = 10,
    ):
        self._pool = ConnectionPool(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
            decode_responses=True,
        )
        self._client = redis.Redis(connection_pool=self._pool)

        # Metrics per keyspace
        self._metrics = {
            "file_analysis": {"hits": 0, "misses": 0},
            "whitelist": {"hits": 0, "misses": 0},
            "threat": {"hits": 0, "misses": 0},
            "pipeline_session": {"hits": 0, "misses": 0},
        }

    # =====================================================================
    # FILE ANALYSIS CACHE (7-day TTL)
    # =====================================================================

    def cache_file_analysis(
        self,
        file_hash: str,
        analysis_data: dict[str, Any],
    ) -> None:
        """
        Cache file analysis results (hash triage, static, sandbox, xgboost).
        Example analysis_data:
        {
            "file_type": "pe",
            "risk_level": "high",
            "static_analysis": {...},
            "sandbox_results": {...},
            "xgboost_results": {...}
        }
        """
        key = f"{self.PREFIX_FILE_ANALYSIS}:{file_hash}"
        value = json.dumps(analysis_data)
        self._client.setex(key, self.TTL_FILE_ANALYSIS, value)

    def get_cached_file_analysis(self, file_hash: str) -> dict[str, Any] | None:
        """
        Retrieve cached file analysis. Returns None if cache miss or expired.
        """
        key = f"{self.PREFIX_FILE_ANALYSIS}:{file_hash}"
        raw = self._client.get(key)

        if raw is None:
            self._metrics["file_analysis"]["misses"] += 1
            return None

        self._metrics["file_analysis"]["hits"] += 1
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def invalidate_file_analysis(self, file_hash: str) -> bool:
        """Remove file analysis cache entry. Returns True if it existed."""
        key = f"{self.PREFIX_FILE_ANALYSIS}:{file_hash}"
        return bool(self._client.delete(key))

    # =====================================================================
    # WHITELIST CACHE (24-hour TTL)
    # =====================================================================

    def is_whitelisted(self, entity: str, entity_type: str = "domain") -> bool:
        """
        Check if domain/hash/url is in the whitelist.
        entity_type: "domain", "hash", "url"
        """
        key = f"{self.PREFIX_WHITELIST}:{entity_type}:{entity.lower().strip()}"
        exists = self._client.exists(key)

        if exists:
            self._metrics["whitelist"]["hits"] += 1
        else:
            self._metrics["whitelist"]["misses"] += 1

        return bool(exists)

    def add_to_whitelist(
        self,
        entity: str,
        entity_type: str = "domain",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Add entity to whitelist with optional metadata.
        entity_type: "domain", "hash", "url"
        """
        key = f"{self.PREFIX_WHITELIST}:{entity_type}:{entity.lower().strip()}"
        value = json.dumps(metadata) if metadata else "1"
        self._client.setex(key, self.TTL_WHITELIST, value)

    def bulk_add_to_whitelist(
        self,
        entities: list[str],
        entity_type: str = "domain",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Bulk add multiple entities to whitelist using pipeline."""
        value = json.dumps(metadata) if metadata else "1"
        pipe = self._client.pipeline()
        for entity in entities:
            key = f"{self.PREFIX_WHITELIST}:{entity_type}:{entity.lower().strip()}"
            pipe.setex(key, self.TTL_WHITELIST, value)
        pipe.execute()

    def remove_from_whitelist(self, entity: str, entity_type: str = "domain") -> bool:
        """Remove entity from whitelist. Returns True if it existed."""
        key = f"{self.PREFIX_WHITELIST}:{entity_type}:{entity.lower().strip()}"
        return bool(self._client.delete(key))

    # =====================================================================
    # THREAT CACHE (24-hour TTL for malicious entities)
    # =====================================================================

    def is_threat(self, entity: str, entity_type: str = "domain") -> bool:
        """
        Check if domain/hash/url is marked as a threat.
        entity_type: "domain", "hash", "url"
        """
        key = f"{self.PREFIX_THREAT}:{entity_type}:{entity.lower().strip()}"
        exists = self._client.exists(key)

        if exists:
            self._metrics["threat"]["hits"] += 1
        else:
            self._metrics["threat"]["misses"] += 1

        return bool(exists)

    def add_threat(
        self,
        entity: str,
        entity_type: str = "domain",
        threat_data: dict[str, Any] | None = None,
    ) -> None:
        """
        Flag entity as a threat with optional metadata (risk_score, source, etc).
        entity_type: "domain", "hash", "url"
        """
        key = f"{self.PREFIX_THREAT}:{entity_type}:{entity.lower().strip()}"
        value = json.dumps(threat_data) if threat_data else "1"
        self._client.setex(key, self.TTL_WHITELIST, value)

    def bulk_add_threats(
        self,
        entities: list[str],
        entity_type: str = "domain",
        threat_data: dict[str, Any] | None = None,
    ) -> None:
        """Bulk add multiple entities as threats using pipeline."""
        value = json.dumps(threat_data) if threat_data else "1"
        pipe = self._client.pipeline()
        for entity in entities:
            key = f"{self.PREFIX_THREAT}:{entity_type}:{entity.lower().strip()}"
            pipe.setex(key, self.TTL_WHITELIST, value)
        pipe.execute()

    def remove_threat(self, entity: str, entity_type: str = "domain") -> bool:
        """Remove entity from threat list. Returns True if it existed."""
        key = f"{self.PREFIX_THREAT}:{entity_type}:{entity.lower().strip()}"
        return bool(self._client.delete(key))

    # =====================================================================
    # PIPELINE SESSION STORE (1-hour TTL for in-flight execution state)
    # =====================================================================

    def store_pipeline_session(
        self,
        correlation_id: str,
        session_data: dict[str, Any],
    ) -> None:
        """
        Store in-flight pipeline execution state.
        session_data example:
        {
            "email_id": 123,
            "stages": ["protocol_check", "email_agent", "file_module", "web_module"],
            "current_stage": "file_module",
            "agent_responses": {...},
            "started_at": "2026-03-24T10:10:10Z"
        }
        """
        key = f"{self.PREFIX_PIPELINE_SESSION}:{correlation_id}"
        value = json.dumps(session_data)
        self._client.setex(key, self.TTL_PIPELINE_SESSION, value)

    def get_pipeline_session(self, correlation_id: str) -> dict[str, Any] | None:
        """
        Retrieve in-flight pipeline session. Returns None if expired or missing.
        """
        key = f"{self.PREFIX_PIPELINE_SESSION}:{correlation_id}"
        raw = self._client.get(key)

        if raw is None:
            self._metrics["pipeline_session"]["misses"] += 1
            return None

        self._metrics["pipeline_session"]["hits"] += 1
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def update_pipeline_session(
        self,
        correlation_id: str,
        updates: dict[str, Any],
    ) -> bool:
        """
        Merge updates into existing pipeline session (non-destructive).
        Returns True if session exists and was updated, False otherwise.
        """
        key = f"{self.PREFIX_PIPELINE_SESSION}:{correlation_id}"
        session = self.get_pipeline_session(correlation_id)

        if session is None:
            return False

        session.update(updates)
        self.store_pipeline_session(correlation_id, session)
        return True

    def remove_pipeline_session(self, correlation_id: str) -> bool:
        """Remove pipeline session (early cleanup). Returns True if it existed."""
        key = f"{self.PREFIX_PIPELINE_SESSION}:{correlation_id}"
        return bool(self._client.delete(key))

    # =====================================================================
    # HEALTH & METRICS
    # =====================================================================

    def ping(self) -> bool:
        """Check if Redis connection is alive."""
        try:
            return self._client.ping()
        except redis.ConnectionError:
            return False

    def get_metrics(self) -> dict[str, Any]:
        """Return hit/miss metrics for all keyspaces."""
        result = {}
        for keyspace, metrics in self._metrics.items():
            total = metrics["hits"] + metrics["misses"]
            hit_rate = (metrics["hits"] / total * 100) if total > 0 else 0.0
            result[keyspace] = {
                "hits": metrics["hits"],
                "misses": metrics["misses"],
                "total": total,
                "hit_rate_pct": round(hit_rate, 2),
            }
        return result

    def reset_metrics(self) -> None:
        """Reset all metrics counters."""
        for keyspace in self._metrics:
            self._metrics[keyspace] = {"hits": 0, "misses": 0}

    def get_info(self) -> dict[str, Any]:
        """Return comprehensive Redis info."""
        try:
            info = self._client.info()
            return {
                "connected": True,
                "redis_version": info.get("redis_version"),
                "used_memory_mb": round(info.get("used_memory", 0) / 1024 / 1024, 2),
                "connected_clients": info.get("connected_clients"),
                "total_commands_processed": info.get("total_commands_processed"),
            }
        except redis.ConnectionError:
            return {"connected": False}

    def clear_all(self) -> None:
        """⚠️ DESTRUCTIVE: Clear all application data from Redis."""
        patterns = [
            f"{self.PREFIX_FILE_ANALYSIS}:*",
            f"{self.PREFIX_WHITELIST}:*",
            f"{self.PREFIX_THREAT}:*",
            f"{self.PREFIX_PIPELINE_SESSION}:*",
        ]
        for pattern in patterns:
            keys = self._client.keys(pattern)
            if keys:
                self._client.delete(*keys)

    def close(self) -> None:
        """Close Redis connection pool."""
        self._pool.disconnect()


# =========================================================================
# Backward compatibility: RedisWhitelistCache wrapper
# =========================================================================

class RedisWhitelistCache:
    """
    Legacy wrapper for backward compatibility.
    Use EnhancedRedisClient directly for new code.
    """

    DEFAULT_TTL = 86400  # 24 hours

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        max_connections: int = 10,
        ttl: int = DEFAULT_TTL,
    ):
        self._client = EnhancedRedisClient(
            host=host,
            port=port,
            db=db,
            password=password,
            max_connections=max_connections,
        )
        # Legacy API stores domain whitelist
        self.ttl = ttl

    def is_whitelisted(self, domain: str) -> bool:
        return self._client.is_whitelisted(domain, entity_type="domain")

    def add(self, domain: str, metadata: dict[str, Any] | None = None) -> None:
        self._client.add_to_whitelist(domain, entity_type="domain", metadata=metadata)

    def remove(self, domain: str) -> bool:
        return self._client.remove_from_whitelist(domain, entity_type="domain")

    def bulk_add(self, domains: list[str], metadata: dict[str, Any] | None = None) -> None:
        self._client.bulk_add_to_whitelist(domains, entity_type="domain", metadata=metadata)

    def get_metadata(self, domain: str) -> dict[str, Any] | None:
        # This is a legacy method; not easily supported by new architecture
        return None

    def get_metrics(self) -> dict[str, Any]:
        return self._client.get_metrics()["whitelist"]

    def reset_metrics(self) -> None:
        self._client.reset_metrics()

    def ping(self) -> bool:
        return self._client.ping()
