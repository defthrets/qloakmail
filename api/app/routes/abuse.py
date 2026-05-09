from __future__ import annotations

import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .. import schemas
from ..db import get_session
from ..deps import get_redis
from ..models import AbuseReport
from ..utils.rate_limit import hit as rl_hit

router = APIRouter(prefix="/abuse", tags=["abuse"])


@router.post("/report")
async def report(
    req: schemas.AbuseReportRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: aioredis.Redis = Depends(get_redis),
):
    ip = request.client.host if request.client else "0.0.0.0"
    allowed, _ = await rl_hit(redis_client, f"rl:abuse:{ip}", limit=10, window_seconds=3600)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit")

    if len(req.body) > 64_000:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "report too large")

    session.add(AbuseReport(
        id=uuid.uuid4(),
        reported_email=req.reported_email,
        reporter_email=req.reporter_email,
        body=req.body,
        headers=req.headers,
        received_at=datetime.now(timezone.utc),
        handled=False,
    ))
    await session.commit()
    return {"ok": True}
