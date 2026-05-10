"""Aggregate-only daily counters for the admin panel.

We deliberately do NOT attribute anything to a user, IP, or session.
Each counter is just `stats:<scope>:YYYY-MM-DD` in Redis, incremented
atomically and expired after 60 days. The admin panel reads back the
last N days as a time-series for charts.

This is the only "analytics" surface we expose -- it counts events,
never identities, which keeps the privacy stance intact.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable

import redis.asyncio as aioredis

# 60 days * 86400 seconds. Counters auto-expire after this window so
# the admin panel can't surface historical data older than that
# without the operator explicitly retaining it elsewhere.
_TTL_SECONDS = 60 * 86400

# Scopes used across the app. Keep the names short -- they become
# part of every redis key. Add new scopes here; don't free-form
# strings at call sites or typos will silently create empty buckets.
SCOPE_BOOT = "boot"            # SPA bootstrap (GET /api/v1/config)
SCOPE_LOGIN_OK = "loginok"     # successful login (SRP M1 matched)
SCOPE_LOGIN_FAIL = "loginfail" # failed login (any 401 from login_verify)
SCOPE_SIGNUP = "signup"        # registration completed
SCOPE_MSG_RX = "msgrx"         # inbound message stored
SCOPE_MSG_TX = "msgtx"         # outbound message handed off to postfix
SCOPE_RL_HIT = "rlhit"         # 429 served by any rate-limited endpoint


def _today_key(scope: str, day: datetime | None = None) -> str:
    d = (day or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    return f"stats:{scope}:{d}"


async def incr(redis_client: aioredis.Redis, scope: str, by: int = 1) -> None:
    """Best-effort increment. Swallows redis errors so a transient cache
    blip never breaks the primary request path. Counter accuracy is
    nice-to-have, not load-bearing."""
    try:
        key = _today_key(scope)
        pipe = redis_client.pipeline()
        pipe.incrby(key, by)
        pipe.expire(key, _TTL_SECONDS)
        await pipe.execute()
    except Exception:
        # Stats are best-effort. Don't propagate.
        pass


async def series(
    redis_client: aioredis.Redis,
    scope: str,
    days: int,
) -> list[tuple[str, int]]:
    """Return [(YYYY-MM-DD, count), ...] for the last `days` days
    inclusive, oldest first. Missing days come back as 0."""
    days = max(1, min(days, 365))
    now = datetime.now(timezone.utc)
    points = [now - timedelta(days=i) for i in range(days - 1, -1, -1)]
    keys = [_today_key(scope, p) for p in points]
    if not keys:
        return []
    try:
        vals = await redis_client.mget(*keys)
    except Exception:
        vals = [None] * len(keys)
    out: list[tuple[str, int]] = []
    for p, v in zip(points, vals):
        n = 0
        if v is not None:
            try:
                n = int(v)
            except (TypeError, ValueError):
                n = 0
        out.append((p.strftime("%Y-%m-%d"), n))
    return out


async def total(
    redis_client: aioredis.Redis,
    scope: str,
    days: int,
) -> int:
    """Sum of `scope` over the last `days` days inclusive."""
    pts = await series(redis_client, scope, days)
    return sum(n for _, n in pts)


async def active_sessions(redis_client: aioredis.Redis) -> int:
    """Live gauge: how many `sess:*` keys exist right now. SCAN-based
    so it doesn't block redis on large keyspaces (KEYS would)."""
    count = 0
    try:
        async for _ in redis_client.scan_iter(match="sess:*", count=500):
            count += 1
    except Exception:
        return 0
    return count
