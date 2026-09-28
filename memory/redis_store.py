"""Redis-backed working memory with explicit TTLs and JSON serialization."""

import json
from typing import Any


class RedisWorkingMemory:
    """A narrow Redis adapter; no persistent data belongs here.

    The dependency is imported lazily so documentation/tests can run without a
    Redis server. Production startup should call ``ping`` and fail closed when
    Redis is required.
    """

    def __init__(self, redis_url: str, namespace: str = "memory", ttl_seconds: int = 3600):
        self.redis_url = redis_url
        self.namespace = namespace
        self.ttl_seconds = ttl_seconds
        self._client = None

    async def _redis(self):
        if self._client is None:
            try:
                import redis.asyncio as redis
            except ImportError as exc:
                raise RuntimeError("Redis support requires `pip install redis`.") from exc
            self._client = redis.from_url(self.redis_url, decode_responses=True)
        return self._client

    def _key(self, scope: str, identifier: str) -> str:
        return f"{self.namespace}:{scope}:{identifier}"

    async def ping(self) -> bool:
        return bool(await (await self._redis()).ping())

    async def put_json(self, scope: str, identifier: str, value: Any, ttl_seconds: int | None = None) -> None:
        client = await self._redis()
        await client.set(self._key(scope, identifier), json.dumps(value), ex=ttl_seconds or self.ttl_seconds)

    async def get_json(self, scope: str, identifier: str, default: Any = None) -> Any:
        raw = await (await self._redis()).get(self._key(scope, identifier))
        return default if raw is None else json.loads(raw)

    async def append_event(self, scope: str, identifier: str, event: dict, max_events: int = 100) -> None:
        """Append a bounded working-memory timeline and renew its TTL."""
        client = await self._redis()
        key = self._key(scope, identifier)
        pipe = client.pipeline(transaction=True)
        pipe.rpush(key, json.dumps(event))
        pipe.ltrim(key, -max_events, -1)
        pipe.expire(key, self.ttl_seconds)
        await pipe.execute()

    async def get_events(self, scope: str, identifier: str) -> list[dict]:
        raw = await (await self._redis()).lrange(self._key(scope, identifier), 0, -1)
        return [json.loads(item) for item in raw]

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
