"""IP allow/deny helpers shared by the auth + signup routes.

The block list itself lives in the `ip_blocks` table (managed via the
admin panel). IPs are stored as HMAC-SHA256 fingerprints — never raw —
so the table is useless without `IP_BAN_SECRET`.

Audit v2 (M6) wired these checks into the auth entry points so a
banned IP can't continue to burn registration / login init capacity.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import IPBlock

_settings = get_settings()


def hmac_ip(ip: str) -> str:
    secret = _settings.effective_ip_ban_secret.encode("utf-8")
    return hmac.new(secret, ip.strip().encode("utf-8"), hashlib.sha256).hexdigest()


async def is_ip_blocked(session: AsyncSession, ip: str) -> bool:
    if not ip:
        return False
    fp = hmac_ip(ip)
    now = datetime.now(timezone.utc)
    r = await session.execute(
        select(IPBlock).where(
            IPBlock.ip_hmac == fp,
            (IPBlock.expires_at.is_(None)) | (IPBlock.expires_at > now),
        )
    )
    return r.scalar_one_or_none() is not None
