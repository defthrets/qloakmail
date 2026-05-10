"""FastAPI dependencies: redis, current account, internal-token guard."""
from __future__ import annotations

import uuid
from typing import AsyncIterator, Optional

import redis.asyncio as aioredis
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db import get_session
from .models import Account
from .srp import hash_token

_settings = get_settings()
_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(_settings.redis_url, decode_responses=False)
    return _redis


async def current_account(
    authorization: str | None = Header(default=None),
    redis_client: aioredis.Redis = Depends(get_redis),
    session: AsyncSession = Depends(get_session),
) -> Account:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization.split(None, 1)[1].strip()
    th = hash_token(token).hex()
    account_id = await redis_client.get(f"sess:{th}")
    if not account_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session")
    aid = uuid.UUID(account_id.decode())
    res = await session.execute(select(Account).where(Account.id == aid))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account not active")
    return account


async def require_internal_token(
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
) -> None:
    if x_internal_token != _settings.internal_api_token:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "internal token required")


async def current_admin(
    authorization: str | None = Header(default=None),
    redis_client: aioredis.Redis = Depends(get_redis),
    session: AsyncSession = Depends(get_session),
) -> Account:
    """Gate admin endpoints — every failure path returns the same 404.

    Audit v2 (M2) noted that mixing 401 (unauth) and 404 (non-admin)
    let an attacker distinguish "admin path exists, you're just not
    one" from "path doesn't exist". We now resolve the session inline
    and *swallow* any auth failure into the same 404 response a
    signed-in non-admin would get. The admin surface is therefore
    indistinguishable from a 404 typo to anyone outside the allow-list.

    Requirements (all enforced silently):
      1. Bearer header present + valid session in Redis.
      2. Session points at an active account.
      3. That account's email is in ADMIN_EMAILS.
    Any failure → HTTP 404 "not found".
    """
    not_found = HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise not_found
    token = authorization.split(None, 1)[1].strip()
    th = hash_token(token).hex()
    account_id = await redis_client.get(f"sess:{th}")
    if not account_id:
        raise not_found
    try:
        aid = uuid.UUID(account_id.decode())
    except ValueError:
        raise not_found
    res = await session.execute(select(Account).where(Account.id == aid))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        raise not_found
    admins = _settings.admin_email_set
    if not admins or account.email.lower() not in admins:
        raise not_found
    return account
