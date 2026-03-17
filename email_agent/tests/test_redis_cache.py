"""
Unit tests for RedisWhitelistCache.

Uses unittest.mock to patch redis.Redis — no live Redis server required.
Run with:  python -m unittest email_agent/tests/test_redis_cache.py -v
"""
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from email_agent.redis_client import RedisWhitelistCache


def _make_cache(**kwargs) -> RedisWhitelistCache:
    """Create a cache instance with a fully mocked Redis client."""
    with patch("redis.ConnectionPool"), patch("redis.Redis") as _:
        cache = RedisWhitelistCache(**kwargs)
        cache._client = MagicMock()   # replace with fresh mock after __init__
    return cache


class TestRedisWhitelistCache(unittest.TestCase):

    # ------------------------------------------------------------------ #
    # is_whitelisted
    # ------------------------------------------------------------------ #

    def test_is_whitelisted_returns_true_for_existing_domain(self):
        """Domain present in Redis → True, hit counter incremented."""
        cache = _make_cache()
        cache._client.exists.return_value = 1   # Redis EXISTS returns 1

        result = cache.is_whitelisted("google.com")

        self.assertTrue(result)
        cache._client.exists.assert_called_once_with("whitelist:google.com")
        self.assertEqual(cache._hits, 1)
        self.assertEqual(cache._misses, 0)

    def test_is_whitelisted_returns_false_for_missing_domain(self):
        """Domain absent from Redis → False, miss counter incremented."""
        cache = _make_cache()
        cache._client.exists.return_value = 0

        result = cache.is_whitelisted("evil.com")

        self.assertFalse(result)
        self.assertEqual(cache._hits, 0)
        self.assertEqual(cache._misses, 1)

    def test_is_whitelisted_normalizes_domain_case(self):
        """Lookups are case-insensitive (key is lowercased)."""
        cache = _make_cache()
        cache._client.exists.return_value = 1

        cache.is_whitelisted("Google.COM")
        cache._client.exists.assert_called_with("whitelist:google.com")

    # ------------------------------------------------------------------ #
    # add
    # ------------------------------------------------------------------ #

    def test_add_sets_key_with_default_ttl(self):
        """add() calls SETEX with 24h TTL."""
        cache = _make_cache()
        cache.add("bank.com")

        cache._client.setex.assert_called_once_with("whitelist:bank.com", 86400, "1")

    def test_add_stores_metadata_as_json(self):
        """add() with metadata stores JSON-encoded value."""
        cache = _make_cache()
        meta = {"reason": "trusted partner", "added_by": "admin"}
        cache.add("partner.com", metadata=meta)

        _, _, value = cache._client.setex.call_args[0]
        self.assertEqual(json.loads(value), meta)

    def test_add_uses_custom_ttl(self):
        """Cache respects custom TTL passed at construction."""
        cache = _make_cache(ttl=3600)   # 1 hour
        cache.add("internal.corp")

        ttl_used = cache._client.setex.call_args[0][1]
        self.assertEqual(ttl_used, 3600)

    # ------------------------------------------------------------------ #
    # remove
    # ------------------------------------------------------------------ #

    def test_remove_existing_domain_returns_true(self):
        cache = _make_cache()
        cache._client.delete.return_value = 1

        result = cache.remove("old.com")

        self.assertTrue(result)
        cache._client.delete.assert_called_once_with("whitelist:old.com")

    def test_remove_nonexistent_domain_returns_false(self):
        cache = _make_cache()
        cache._client.delete.return_value = 0

        result = cache.remove("ghost.com")
        self.assertFalse(result)

    # ------------------------------------------------------------------ #
    # bulk_add
    # ------------------------------------------------------------------ #

    def test_bulk_add_uses_pipeline(self):
        """bulk_add() should execute via a Redis pipeline."""
        cache = _make_cache()
        pipe_mock = MagicMock()
        cache._client.pipeline.return_value = pipe_mock

        domains = ["a.com", "b.com", "c.com"]
        cache.bulk_add(domains)

        cache._client.pipeline.assert_called_once()
        self.assertEqual(pipe_mock.setex.call_count, 3)
        pipe_mock.execute.assert_called_once()

    # ------------------------------------------------------------------ #
    # Metrics
    # ------------------------------------------------------------------ #

    def test_metrics_track_hits_and_misses(self):
        """get_metrics() returns correct counts and hit rate."""
        cache = _make_cache()
        cache._client.exists.side_effect = [1, 1, 0]   # 2 hits, 1 miss

        cache.is_whitelisted("a.com")
        cache.is_whitelisted("b.com")
        cache.is_whitelisted("c.com")

        metrics = cache.get_metrics()
        self.assertEqual(metrics["hits"], 2)
        self.assertEqual(metrics["misses"], 1)
        self.assertEqual(metrics["total"], 3)
        self.assertAlmostEqual(metrics["hit_rate_pct"], 66.67, places=1)

    def test_reset_metrics(self):
        """reset_metrics() zeroes all counters."""
        cache = _make_cache()
        cache._hits = 5
        cache._misses = 3
        cache.reset_metrics()

        metrics = cache.get_metrics()
        self.assertEqual(metrics["hits"], 0)
        self.assertEqual(metrics["misses"], 0)
        self.assertEqual(metrics["total"], 0)

    # ------------------------------------------------------------------ #
    # Lookup latency
    # ------------------------------------------------------------------ #

    def test_lookup_latency_under_1ms(self):
        """is_whitelisted() must complete in under 1ms (mocked Redis)."""
        cache = _make_cache()
        cache._client.exists.return_value = 1

        start = time.perf_counter()
        cache.is_whitelisted("fast.com")
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertLess(elapsed_ms, 1.0, f"Lookup took {elapsed_ms:.3f}ms, expected <1ms")

    # ------------------------------------------------------------------ #
    # Ping / health
    # ------------------------------------------------------------------ #

    def test_ping_returns_true_when_connected(self):
        cache = _make_cache()
        cache._client.ping.return_value = True
        self.assertTrue(cache.ping())

    def test_ping_returns_false_on_connection_error(self):
        import redis
        cache = _make_cache()
        cache._client.ping.side_effect = redis.ConnectionError

        self.assertFalse(cache.ping())


if __name__ == "__main__":
    unittest.main()
