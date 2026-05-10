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
    account: Account = Depends(current_account),
) -> Account:
    """Gate admin endpoints. Requires:
      1. A normal authenticated session (current_account passed).
      2. The account email matches an entry in ADMIN_EMAILS.
    Returns 404 (not 403) when not an admin so the existence of admin
    endpoints isn't enumerable to a regular signed-in user — they'll
    see the same response as if the path didn't exist.
    """
    admins = _settings.admin_email_set
    if not admins or account.email.lower() not in admins:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return account
