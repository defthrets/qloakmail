"""Tiny token-bucket rate limiter on top of Redis."""
from __future__ import annotations

import time
from typing import Optional

import redis.asyncio as aioredis


async def hit(
    redis_client: aioredis.Redis,
    key: str,
    *,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """Returns (allowed, remaining). Implements a fixed-window counter
    sufficient for signup, login attempts, and abuse endpoints. Anything
    higher-volume should use a leaky bucket — but this isn't that."""
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, window_seconds)
    count, _ = await pipe.execute()
    allowed = count <= limit
    remaining = max(0, limit - count)
    return allowed, remaining
