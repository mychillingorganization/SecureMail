"""
Redis Message Bus — Pub/Sub + Request-Response messaging.
Kênh: agent:email:*, agent:file:*, agent:web:*, orchestrator:*
Connection pooling với tối đa 20 kết nối.
"""
import asyncio
import json
import logging
import uuid
from collections.abc import Callable

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)


class RedisBus:
    """
    Redis message bus với pub/sub và request-response pattern.
    Hỗ trợ connection pooling và tự động cleanup.
    """

    # Các prefix kênh chuẩn
    CHANNEL_EMAIL = "agent:email"
    CHANNEL_FILE = "agent:file"
    CHANNEL_WEB = "agent:web"
    CHANNEL_ORCHESTRATOR = "orchestrator"

    def __init__(self, redis_url: str = "redis://redis:6379/0", max_connections: int = 20):
        self.redis_url = redis_url
        self.max_connections = max_connections
        self._pool: aioredis.ConnectionPool | None = None
        self._client: aioredis.Redis | None = None
        self._pubsub: aioredis.client.PubSub | None = None

    async def connect(self):
        """Khởi tạo connection pool và kết nối Redis."""
        self._pool = aioredis.ConnectionPool.from_url(
            self.redis_url,
            max_connections=self.max_connections,
            decode_responses=True,
        )
        self._client = aioredis.Redis(connection_pool=self._pool)
        # Kiểm tra kết nối
        await self._client.ping()
        logger.info(f"Redis connected: {self.redis_url} (max_connections={self.max_connections})")

    async def publish(self, channel: str, message: dict) -> int:
        """
        Publish message đến một kênh.
        Returns: số subscriber nhận được.
        """
        if not self._client:
            raise RuntimeError("RedisBus chưa kết nối. Gọi connect() trước.")
        payload = json.dumps(message, default=str)
        return await self._client.publish(channel, payload)

    async def publish_request(
        self,
        channel: str,
        payload: dict,
        timeout: float = 30.0,
    ) -> dict:
        """
        Publish request và chờ response (request-response pattern).
        Tạo kênh response duy nhất, subscribe, gửi request, chờ phản hồi.
        """
        if not self._client:
            raise RuntimeError("RedisBus chưa kết nối. Gọi connect() trước.")

        request_id = str(uuid.uuid4())
        response_channel = f"{self.CHANNEL_ORCHESTRATOR}:response:{request_id}"

        # Subscribe trước khi publish
        pubsub = self._client.pubsub()
        await pubsub.subscribe(response_channel)

        try:
            # Gửi request kèm metadata
            request_msg = {
                "request_id": request_id,
                "response_channel": response_channel,
                **payload,
            }
            await self.publish(f"{channel}:request", request_msg)
            logger.debug(f"Published request {request_id} to {channel}:request")

            # Chờ response với timeout
            response = await self._wait_for_response(pubsub, timeout)
            return response

        finally:
            # Cleanup subscription
            await pubsub.unsubscribe(response_channel)
            await pubsub.close()

    async def _wait_for_response(self, pubsub, timeout: float) -> dict:
        """Chờ response từ pubsub với timeout."""
        deadline = asyncio.get_event_loop().time() + timeout
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    return json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    return {"raw": message["data"]}
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(f"Response timeout sau {timeout}s")
        raise TimeoutError("PubSub stream kết thúc bất ngờ")

    async def subscribe(self, channel_pattern: str, callback: Callable):
        """
        Subscribe vào kênh theo pattern và gọi callback khi nhận message.
        Callback nhận (channel, message_dict).
        """
        if not self._client:
            raise RuntimeError("RedisBus chưa kết nối. Gọi connect() trước.")

        self._pubsub = self._client.pubsub()
        await self._pubsub.psubscribe(channel_pattern)

        async for message in self._pubsub.listen():
            if message["type"] == "pmessage":
                try:
                    data = json.loads(message["data"])
                except (json.JSONDecodeError, TypeError):
                    data = {"raw": message["data"]}
                await callback(message["channel"], data)

    async def respond(self, response_channel: str, payload: dict):
        """Gửi response đến kênh response cụ thể."""
        await self.publish(response_channel, payload)

    async def close(self):
        """Đóng tất cả kết nối."""
        if self._pubsub:
            await self._pubsub.close()
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis disconnected")
