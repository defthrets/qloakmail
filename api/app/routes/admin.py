"""Admin panel API — stats, accounts, IP blocks, audit log, charts.

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

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_session
from ..deps import current_admin, get_redis
from ..models import Account, AdminAction, IPBlock, Message
from ..utils import stats as st
from ..utils.ip_blocks import hmac_ip, is_ip_blocked  # noqa: F401 (re-export)

# include_in_schema=False keeps the admin surface out of /api/openapi.json
# and /api/docs so the existence of an admin panel isn't discoverable
# without prior knowledge of the path. Audit v2 (M2).
router = APIRouter(prefix="/admin", tags=["admin"], include_in_schema=False)
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
    # Aggregate-only event counters (no per-IP / per-user attribution).
    # Sourced from redis daily buckets that auto-expire after 60 days.
    boot_pings_24h: int = 0
    boot_pings_7d: int = 0
    login_ok_24h: int = 0
    login_fail_24h: int = 0
    rate_limit_hits_24h: int = 0
    msg_rx_24h: int = 0
    msg_rx_7d: int = 0
    active_sessions: int = 0


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


async def _audit(
    session: AsyncSession,
    admin: Account,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    target_label: str | None = None,
    details: str | None = None,
) -> None:
    session.add(AdminAction(
        id=uuid.uuid4(),
        admin_id=admin.id,
        admin_email=admin.email,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        details=details,
        created_at=_now(),
    ))


# ----------------------------------------------------------------- stats

@router.get("/stats", response_model=AdminStats)
async def admin_stats(
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
    redis_client=Depends(get_redis),
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

    # Aggregate event counters from redis (24h = today's bucket only,
    # 7d = sum of last 7 daily buckets). These are best-effort -- if
    # redis is down the values return as 0 and the panel still loads.
    boot_24h = await st.total(redis_client, st.SCOPE_BOOT, 1)
    boot_7d  = await st.total(redis_client, st.SCOPE_BOOT, 7)
    loginok_24h = await st.total(redis_client, st.SCOPE_LOGIN_OK, 1)
    loginfail_24h = await st.total(redis_client, st.SCOPE_LOGIN_FAIL, 1)
    rl_24h = await st.total(redis_client, st.SCOPE_RL_HIT, 1)
    msgrx_24h = await st.total(redis_client, st.SCOPE_MSG_RX, 1)
    msgrx_7d  = await st.total(redis_client, st.SCOPE_MSG_RX, 7)
    sessions_live = await st.active_sessions(redis_client)

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
        boot_pings_24h=boot_24h,
        boot_pings_7d=boot_7d,
        login_ok_24h=loginok_24h,
        login_fail_24h=loginfail_24h,
        rate_limit_hits_24h=rl_24h,
        msg_rx_24h=msgrx_24h,
        msg_rx_7d=msgrx_7d,
        active_sessions=sessions_live,
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
    admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    a.status = "banned"
    await _audit(session, admin, "ban_account", "account",
                 str(a.id), a.email, body.reason)
    await session.commit()
    return {"ok": True, "status": a.status, "reason": body.reason}


@router.post("/account/{account_id}/unban")
async def unban_account(
    account_id: uuid.UUID,
    admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    a.status = "active"
    await _audit(session, admin, "unban_account", "account", str(a.id), a.email)
    await session.commit()
    return {"ok": True, "status": a.status}


@router.post("/account/{account_id}/revoke-sessions")
async def revoke_sessions(
    account_id: uuid.UUID,
    admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
    redis_client = Depends(get_redis),
):
    """Drop all live session tokens for an account from Redis.
    Forces every signed-in client of that account to re-authenticate
    on its next API call (a returning user hits the unlock view).
    """
    a = (await session.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    # Sessions table has rows pointing to redis-stored tokens. Walk
    # the redis keyspace for sess:* and delete any that map to this
    # account_id.
    deleted = 0
    target = str(a.id).encode()
    async for key in redis_client.scan_iter(match="sess:*", count=200):
        val = await redis_client.get(key)
        if val == target:
            await redis_client.delete(key)
            deleted += 1
    await _audit(session, admin, "revoke_sessions", "account",
                 str(a.id), a.email, f"{deleted} session(s)")
    await session.commit()
    return {"ok": True, "revoked": deleted}


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
    label = a.email
    await _audit(session, admin, "delete_account", "account", str(a.id), label)
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
    admin: Account = Depends(current_admin),
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
    await _audit(session, admin, "add_ip_block", "ip_block",
                 str(blk.id), fp[:12] + "…", body.reason)
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
    admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    b = (await session.execute(select(IPBlock).where(IPBlock.id == block_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    await _audit(session, admin, "remove_ip_block", "ip_block",
                 str(b.id), b.ip_hmac[:12] + "…")
    await session.delete(b)
    await session.commit()
    return {"ok": True}


# ----------------------------------------------------------------- timeseries

class TimeSeriesPoint(BaseModel):
    date: str   # YYYY-MM-DD
    count: int


@router.get("/timeseries/signups", response_model=list[TimeSeriesPoint])
async def timeseries_signups(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    days = max(7, min(365, days))
    cutoff = _now() - timedelta(days=days - 1)
    bucket = func.date_trunc("day", Account.created_at)
    rows = (await session.execute(
        select(bucket, func.count())
        .where(Account.created_at >= cutoff)
        .group_by(bucket)
        .order_by(bucket)
    )).all()
    seen = {row[0].date(): int(row[1]) for row in rows if row[0]}
    out: list[TimeSeriesPoint] = []
    for i in range(days):
        d = (cutoff + timedelta(days=i)).date()
        out.append(TimeSeriesPoint(date=d.isoformat(), count=seen.get(d, 0)))
    return out


@router.get("/timeseries/messages", response_model=list[TimeSeriesPoint])
async def timeseries_messages(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    days = max(7, min(365, days))
    cutoff = _now() - timedelta(days=days - 1)
    bucket = func.date_trunc("day", Message.received_at)
    rows = (await session.execute(
        select(bucket, func.count())
        .where(Message.received_at >= cutoff)
        .group_by(bucket)
        .order_by(bucket)
    )).all()
    seen = {row[0].date(): int(row[1]) for row in rows if row[0]}
    out: list[TimeSeriesPoint] = []
    for i in range(days):
        d = (cutoff + timedelta(days=i)).date()
        out.append(TimeSeriesPoint(date=d.isoformat(), count=seen.get(d, 0)))
    return out


# ----------------------------------------------------------------- counter timeseries
# These wrap the aggregate redis counters (SPA boot / login outcomes /
# rate-limit hits). They return the same shape as the DB-backed series
# so the SPA's chart helper can render either source identically.

async def _counter_series(redis_client, scope: str, days: int) -> list[TimeSeriesPoint]:
    days = max(7, min(60, days))
    rows = await st.series(redis_client, scope, days)
    return [TimeSeriesPoint(date=d, count=n) for d, n in rows]


@router.get("/timeseries/visitors", response_model=list[TimeSeriesPoint])
async def timeseries_visitors(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    redis_client=Depends(get_redis),
):
    """SPA boot pings -- one per /api/v1/config call. Best signal we
    have for daily visitors without storing any identifier."""
    return await _counter_series(redis_client, st.SCOPE_BOOT, days)


@router.get("/timeseries/login-ok", response_model=list[TimeSeriesPoint])
async def timeseries_login_ok(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    redis_client=Depends(get_redis),
):
    return await _counter_series(redis_client, st.SCOPE_LOGIN_OK, days)


@router.get("/timeseries/login-fail", response_model=list[TimeSeriesPoint])
async def timeseries_login_fail(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    redis_client=Depends(get_redis),
):
    return await _counter_series(redis_client, st.SCOPE_LOGIN_FAIL, days)


@router.get("/timeseries/rate-limit", response_model=list[TimeSeriesPoint])
async def timeseries_rate_limit(
    days: int = 30,
    _admin: Account = Depends(current_admin),
    redis_client=Depends(get_redis),
):
    return await _counter_series(redis_client, st.SCOPE_RL_HIT, days)
    return out


# ----------------------------------------------------------------- top storage

class StorageEntry(BaseModel):
    account_id: uuid.UUID
    email: str
    used_bytes: int
    quota_bytes: int
    message_count: int


@router.get("/top-storage", response_model=list[StorageEntry])
async def top_storage(
    limit: int = 10,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    limit = max(1, min(50, limit))
    rows = (await session.execute(
        select(Account).order_by(Account.used_bytes.desc()).limit(limit)
    )).scalars().all()
    if not rows:
        return []
    ids = [a.id for a in rows]
    mc_rows = (await session.execute(
        select(Message.account_id, func.count())
        .where(Message.account_id.in_(ids))
        .group_by(Message.account_id)
    )).all()
    mc = {row[0]: int(row[1]) for row in mc_rows}
    return [
        StorageEntry(
            account_id=a.id, email=a.email,
            used_bytes=a.used_bytes, quota_bytes=a.quota_bytes,
            message_count=mc.get(a.id, 0),
        ) for a in rows
    ]


# ----------------------------------------------------------------- audit log

class AuditEntry(BaseModel):
    id: uuid.UUID
    admin_email: str
    action: str
    target_type: str | None
    target_label: str | None
    details: str | None
    created_at: datetime


@router.get("/audit-log", response_model=list[AuditEntry])
async def audit_log(
    limit: int = 100,
    offset: int = 0,
    _admin: Account = Depends(current_admin),
    session: AsyncSession = Depends(get_session),
):
    limit = max(1, min(500, limit))
    offset = max(0, offset)
    rows = (await session.execute(
        select(AdminAction)
        .order_by(AdminAction.created_at.desc())
        .offset(offset).limit(limit)
    )).scalars().all()
    return [
        AuditEntry(
            id=a.id, admin_email=a.admin_email, action=a.action,
            target_type=a.target_type, target_label=a.target_label,
            details=a.details, created_at=a.created_at,
        ) for a in rows
    ]


