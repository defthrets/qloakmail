"""Admin panel API.

Behind the `current_admin` dependency, which requires:
  1. A valid authenticated session (normal Bearer token).
  2. The account email is in `ADMIN_EMAILS` (env var, comma-separated).

Non-admins get 404 (not 403) on every endpoint so the surface isn't
enumerable to regular users.

Endpoints:
  GET    /admin/stats                           — high-level counters
  GET    /admin/accounts?q=&offset=&limit=       — paginated account list
  GET    /admin/account/{id}                    — one account, with stats
  POST   /admin/account/{id}/ban  body=reason   — set status=banned
  POST   /admin/account/{id}/unban              — set status=active
  DELETE /admin/account/{id}                    — hard delete (cascades)

  GET    /admin/ip-blocks                       — list active IP blocks
  POST   /admin/ip-blocks  body={ip,reason}      — hash + store
  DELETE /admin/ip-blocks/{id}                  — remove an IP block

The IP block list itself is enforced by `is_ip_blocked()` which the
auth + signup paths can call. (Wiring those callers is intentionally
left for a follow-up; this commit just lands the storage and admin
UI so the block list exists for use.)
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_session
from ..deps import current_admin
from ..models import Account, IPBlock, Message

router = APIRouter(prefix="/admin", tags=["admin"])
_settings = get_settings()


# ----------------------------------------------------------------- response models

class AccountSummary(BaseModel):
    id: uuid.UUID
    email: str
    status: str
    quota_bytes: int
    used_bytes: int
    invite_code: str | None
    created_at: datetime
    last_login_at: datetime | None
    message_count: int = 0


class AdminStats(BaseModel):
    accounts_total: int
    accounts_active: int
    accounts_banned: int
    accounts_pending: int
    signups_24h: int
    signups_7d: int
    signups_30d: int
    messages_total: int
    messages_24h: int
    storage_bytes_used: int
    ip_blocks_active: int


class AccountListResponse(BaseModel):
    items: list[AccountSummary]
    total: int
    offset: int
    limit: int


class BanRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class IPBlockRequest(BaseModel):
    ip: str = Field(..., min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=500)
    ttl_hours: int | None = Field(default=None, ge=1, le=24 * 365)


class IPBlockOut(BaseModel):
    id: uuid.UUID
    # The hash itself is the stored identity. We expose only a short
    # prefix in the UI (e.g. "a1b2c3d4...") so admins can identify
    # blocks without us reconstructing the IP.
    fingerprint: str
    reason: str | None
    created_at: datetime
    expires_at: datetime | None


# ----------------------------------------------------------------- helpers

def _now() -> datetime:
    return datetime.now(timezone.utc)


def hmac_ip(ip: str) -> str:
    secret = _settings.effective_ip_ban_secret.encode()
    return hmac.new(secret, ip.encode(), hashlib.sha256).hexdigest()


# ----------------------------------------------------------------- stats

@router.get("/stats", response_model=AdminStats)
async def admin_stats(
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    now = _now()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d  = now - timedelta(days=7)
    cutoff_30d = now - timedelta(days=30)

    async def _count(stmt):
        r = await session.execute(stmt)
        return int(r.scalar_one() or 0)

    accounts_total   = await _count(select(func.count()).select_from(Account))
    accounts_active  = await _count(select(func.count()).select_from(Account).where(Account.status == "active"))
    accounts_banned  = await _count(select(func.count()).select_from(Account).where(Account.status == "banned"))
    accounts_pending = await _count(select(func.count()).select_from(Account).where(Account.status == "pending"))

    signups_24h = await _count(select(func.count()).select_from(Account).where(Account.created_at >= cutoff_24h))
    signups_7d  = await _count(select(func.count()).select_from(Account).where(Account.created_at >= cutoff_7d))
    signups_30d = await _count(select(func.count()).select_from(Account).where(Account.created_at >= cutoff_30d))

    messages_total = await _count(select(func.count()).select_from(Message))
    messages_24h   = await _count(select(func.count()).select_from(Message).where(Message.received_at >= cutoff_24h))

    storage_used = await _count(select(func.coalesce(func.sum(Account.used_bytes), 0)).select_from(Account))

    ip_blocks_active = await _count(
        select(func.count()).select_from(IPBlock).where(
            (IPBlock.expires_at.is_(None)) | (IPBlock.expires_at > now)
        )
    )

    return AdminStats(
        accounts_total=accounts_total,
        accounts_active=accounts_active,
        accounts_banned=accounts_banned,
        accounts_pending=accounts_pending,
        signups_24h=signups_24h,
        signups_7d=signups_7d,
        signups_30d=signups_30d,
        messages_total=messages_total,
        messages_24h=messages_24h,
        storage_bytes_used=storage_used,
        ip_blocks_active=ip_blocks_active,
    )


# ----------------------------------------------------------------- accounts

@router.get("/accounts", response_model=AccountListResponse)
async def list_accounts(
    q: str | None = None,
    offset: int = 0,
    limit: int = 50,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    limit = max(1, min(200, limit))
    offset = max(0, offset)

    base = select(Account).order_by(Account.created_at.desc())
    cnt  = select(func.count()).select_from(Account)
    if q:
        like = f"%{q.strip().lower()}%"
        base = base.where(func.lower(Account.email).like(like))
        cnt  = cnt.where(func.lower(Account.email).like(like))

    total = int((await session.execute(cnt)).scalar_one() or 0)
    rows  = (await session.execute(base.offset(offset).limit(limit))).scalars().all()

    # Per-account message counts in one round-trip.
    if rows:
        ids = [a.id for a in rows]
        mc_rows = (await session.execute(
            select(Message.account_id, func.count())
            .where(Message.account_id.in_(ids))
            .group_by(Message.account_id)
        )).all()
        mc = {row[0]: int(row[1]) for row in mc_rows}
    else:
        mc = {}

    items = [
        AccountSummary(
            id=a.id,
            email=a.email,
            status=a.status,
            quota_bytes=a.quota_bytes,
            used_bytes=a.used_bytes,
            invite_code=a.invite_code,
            created_at=a.created_at,
            last_login_at=a.last_login_at,
            message_count=mc.get(a.id, 0),
        )
        for a in rows
    ]
    return AccountListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/account/{account_id}", response_model=AccountSummary)
async def get_account(
    account_id: uuid.UUID,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    mc = int((await session.execute(
        select(func.count()).select_from(Message).where(Message.account_id == a.id)
    )).scalar_one() or 0)
    return AccountSummary(
        id=a.id, email=a.email, status=a.status,
        quota_bytes=a.quota_bytes, used_bytes=a.used_bytes,
        invite_code=a.invite_code,
        created_at=a.created_at, last_login_at=a.last_login_at,
        message_count=mc,
    )


@router.post("/account/{account_id}/ban")
async def ban_account(
    account_id: uuid.UUID,
    body: BanRequest,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    a.status = "banned"
    await session.commit()
    return {"ok": True, "status": a.status, "reason": body.reason}


@router.post("/account/{account_id}/unban")
async def unban_account(
    account_id: uuid.UUID,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    a.status = "active"
    await session.commit()
    return {"ok": True, "status": a.status}


@router.delete("/account/{account_id}")
async def delete_account(
    account_id: uuid.UUID,
    admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    if account_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete your own admin account here")
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    await session.delete(a)
    await session.commit()
    return {"ok": True}


# ----------------------------------------------------------------- IP blocks

@router.get("/ip-blocks", response_model=list[IPBlockOut])
async def list_ip_blocks(
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    rows = (await session.execute(
        select(IPBlock).order_by(IPBlock.created_at.desc()).limit(500)
    )).scalars().all()
    return [
        IPBlockOut(
            id=b.id,
            fingerprint=b.ip_hmac[:12] + "…",
            reason=b.reason,
            created_at=b.created_at,
            expires_at=b.expires_at,
        )
        for b in rows
    ]


@router.post("/ip-blocks", response_model=IPBlockOut)
async def add_ip_block(
    body: IPBlockRequest,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    fp = hmac_ip(body.ip.strip())
    existing = (await session.execute(
        select(IPBlock).where(IPBlock.ip_hmac == fp)
    )).scalar_one_or_none()
    if existing:
        return IPBlockOut(
            id=existing.id,
            fingerprint=existing.ip_hmac[:12] + "…",
            reason=existing.reason,
            created_at=existing.created_at,
            expires_at=existing.expires_at,
        )
    expires_at = None
    if body.ttl_hours:
        expires_at = _now() + timedelta(hours=body.ttl_hours)
    blk = IPBlock(
        id=uuid.uuid4(),
        ip_hmac=fp,
        reason=body.reason,
        created_at=_now(),
        expires_at=expires_at,
    )
    session.add(blk)
    await session.commit()
    return IPBlockOut(
        id=blk.id,
        fingerprint=blk.ip_hmac[:12] + "…",
        reason=blk.reason,
        created_at=blk.created_at,
        expires_at=blk.expires_at,
    )


@router.delete("/ip-blocks/{block_id}")
async def remove_ip_block(
    block_id: uuid.UUID,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    b = (await session.execute(select(IPBlock).where(IPBlock.id == block_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    await session.delete(b)
    await session.commit()
    return {"ok": True}


# Used by auth/signup paths to check if a request IP is blocked. Wiring
# left for a follow-up; the function is here so callers can adopt it.
async def is_ip_blocked(session: AsyncSession, ip: str) -> bool:
    if not ip:
        return False
    fp = hmac_ip(ip)
    now = _now()
    r = await session.execute(
        select(IPBlock).where(
            IPBlock.ip_hmac == fp,
            (IPBlock.expires_at.is_(None)) | (IPBlock.expires_at > now),
        )
    )
    return r.scalar_one_or_none() is not None
