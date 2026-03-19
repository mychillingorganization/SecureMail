"""
Redis Message Bus — Pub/Sub + Request-Response messaging.
Kênh: agent:email:*, agent:file:*, agent:web:*, orchestrator:*
Connection pooling với tối đa 20 kết nối.
"""

import asyncio
import json
import logging
import uuid
from contextlib import suppress
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
            response = await self._wait_for_response(pubsub, request_id=request_id, timeout=timeout)
            return response

        finally:
            # Cleanup subscription
            await pubsub.unsubscribe(response_channel)
            await pubsub.close()

    async def _wait_for_response(self, pubsub, request_id: str, timeout: float) -> dict:
        """Chờ response từ pubsub với timeout cứng và kiểm tra request_id."""
        poll_interval = 0.1
        deadline = asyncio.get_running_loop().time() + timeout

        while True:
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError(f"Response timeout sau {timeout}s")

            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=poll_interval)
            if message is None:
                continue

            payload = self._parse_message_data(message.get("data"))
            if self._is_matching_response(payload, request_id=request_id):
                return payload

    def _parse_message_data(self, raw_data) -> dict:
        """Parse dữ liệu message từ Redis thành dict."""
        if isinstance(raw_data, dict):
            return raw_data
        try:
            parsed = json.loads(raw_data)
            if isinstance(parsed, dict):
                return parsed
            return {"raw": parsed}
        except (json.JSONDecodeError, TypeError):
            return {"raw": raw_data}

    def _is_matching_response(self, payload: dict, request_id: str) -> bool:
        """Kiểm tra payload response có khớp request_id hay không."""
        payload_request_id = payload.get("request_id")
        if payload_request_id is None:
            # Kênh response đã là duy nhất theo request_id; cho phép tương thích ngược.
            return True
        if payload_request_id != request_id:
            logger.warning(
                "Bỏ qua response không khớp request_id: expected=%s actual=%s",
                request_id,
                payload_request_id,
            )
            return False
        return True

    async def subscribe(self, channel_pattern: str, callback: Callable):
        """
        Subscribe vào kênh theo pattern và gọi callback khi nhận message.
        Callback nhận (channel, message_dict).
        """
        if not self._client:
            raise RuntimeError("RedisBus chưa kết nối. Gọi connect() trước.")

        pubsub = self._client.pubsub()
        self._pubsub = pubsub
        await pubsub.psubscribe(channel_pattern)

        try:
            async for message in pubsub.listen():
                if message["type"] == "pmessage":
                    data = self._parse_message_data(message.get("data"))
                    await callback(message["channel"], data)
        finally:
            with suppress(Exception):
                await pubsub.punsubscribe(channel_pattern)
            with suppress(Exception):
                await pubsub.close()
            if self._pubsub is pubsub:
                self._pubsub = None

    async def respond(self, response_channel: str, payload: dict):
        """Gửi response đến kênh response cụ thể."""
        await self.publish(response_channel, payload)

    async def close(self):
        """Đóng tất cả kết nối."""
        if self._pubsub:
            with suppress(Exception):
                await self._pubsub.close()
            self._pubsub = None
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis disconnected")
