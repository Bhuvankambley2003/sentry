"""Redis pub/sub and stream helpers for all HomeGuard services."""
from __future__ import annotations

import json
import asyncio
from typing import Any, AsyncIterator, Callable, Awaitable

import redis.asyncio as aioredis
from pydantic import BaseModel

from libs.common.config import get_settings
from libs.common.logging import get_logger

logger = get_logger(__name__, service="bus")


class EventBus:
    """Thin wrapper around Redis pub/sub."""

    def __init__(self, redis_url: str | None = None) -> None:
        self._url = redis_url or get_settings().redis_url
        self._client: aioredis.Redis | None = None

    async def connect(self) -> None:
        self._client = aioredis.from_url(self._url, decode_responses=True)
        await self._client.ping()
        logger.info("Redis connected", extra={"redis_url": self._url})

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def publish(self, topic: str, payload: BaseModel | dict[str, Any]) -> None:
        if self._client is None:
            raise RuntimeError("EventBus not connected")
        data = payload.model_dump_json() if isinstance(payload, BaseModel) else json.dumps(payload, default=str)
        await self._client.publish(topic, data)
        logger.debug("Published event", extra={"topic": topic})

    async def subscribe(
        self,
        topics: list[str],
        handler: Callable[[str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Subscribe to topics and call handler for each message. Runs forever."""
        if self._client is None:
            raise RuntimeError("EventBus not connected")
        pubsub = self._client.pubsub()
        await pubsub.subscribe(*topics)
        logger.info("Subscribed to topics", extra={"topics": topics})
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await handler(message["channel"], data)
                except Exception as exc:
                    logger.error("Event handler error", extra={"exc": str(exc), "channel": message.get("channel")})

    async def check_connection(self) -> bool:
        """Return True if Redis is reachable."""
        try:
            client = aioredis.from_url(self._url, decode_responses=True)
            await client.ping()
            await client.aclose()
            return True
        except Exception:
            return False


_bus: EventBus | None = None


def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
