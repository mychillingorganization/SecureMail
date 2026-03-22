"""
Tests cho RedisBus — Kiểm thử message bus.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from redis_bus import RedisBus


def run_async(coro):
    """Helper để chạy async test."""
    return asyncio.run(coro)


class TestRedisBus(unittest.TestCase):
    # Test 1: Khởi tạo connection pool parameters
    def test_init_parameters(self):
        bus = RedisBus(redis_url="redis://localhost:6379/0", max_connections=20)
        self.assertEqual(bus.redis_url, "redis://localhost:6379/0")
        self.assertEqual(bus.max_connections, 20)
        self.assertIsNone(bus._pool)
        self.assertIsNone(bus._client)

    # Test 2: Channel constants đúng
    def test_channel_constants(self):
        self.assertEqual(RedisBus.CHANNEL_EMAIL, "agent:email")
        self.assertEqual(RedisBus.CHANNEL_FILE, "agent:file")
        self.assertEqual(RedisBus.CHANNEL_WEB, "agent:web")
        self.assertEqual(RedisBus.CHANNEL_ORCHESTRATOR, "orchestrator")

    # Test 3: Publish khi chưa kết nối → raise RuntimeError
    def test_publish_without_connect_raises(self):
        bus = RedisBus()
        with self.assertRaises(RuntimeError):
            run_async(bus.publish("test:channel", {"data": "test"}))

    # Test 4: publish_request khi chưa kết nối → raise RuntimeError
    def test_publish_request_without_connect_raises(self):
        bus = RedisBus()
        with self.assertRaises(RuntimeError):
            run_async(bus.publish_request("test:channel", {"data": "test"}))

    # Test 5: Default max_connections = 20
    def test_default_max_connections(self):
        bus = RedisBus()
        self.assertEqual(bus.max_connections, 20)

    # Test 6: Connect tạo pool và client
    @patch("redis.asyncio.ConnectionPool.from_url")
    @patch("redis.asyncio.Redis")
    def test_connect_creates_pool_and_client(self, mock_redis_cls, mock_pool_from_url):
        bus = RedisBus(redis_url="redis://test:6379/0", max_connections=15)

        mock_pool = MagicMock()
        mock_pool_from_url.return_value = mock_pool

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()
        mock_redis_cls.return_value = mock_client

        run_async(bus.connect())

        mock_pool_from_url.assert_called_once_with(
            "redis://test:6379/0",
            max_connections=15,
            decode_responses=True,
        )
        self.assertIsNotNone(bus._pool)


if __name__ == "__main__":
    unittest.main()
