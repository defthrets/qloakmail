"""Endpoints used by the encrypt-pipe and other in-cluster components.
Guarded by an X-Internal-Token shared secret. Never exposed via nginx."""
from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import schemas
from ..db import get_session
from ..deps import get_redis, require_internal_token
from ..models import Account, Folder, Message
from ..schemas import EmailStr
from ..utils import stats

router = APIRouter(
    prefix="/internal",
    tags=["internal"],
    dependencies=[Depends(require_internal_token)],
)

MAILSTORE_ROOT = Path(os.environ.get("MAILSTORE_PATH", "/var/mail"))


@router.get("/pubkey/{email}", response_model=schemas.InternalPubkeyResponse)
async def internal_pubkey(email: str, session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(Account).where(Account.email == email))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such account")
    return schemas.InternalPubkeyResponse(
        email=account.email,
        pubkey_armored=account.pubkey_armored,
        pubkey_fpr=account.pubkey_fpr,
    )


class DeliveredMessage(BaseModel):
    rcpt: EmailStr
    storage_path: str
    size_bytes: int
    encrypted_preview_b64: str | None = None
    folder: str = "Inbox"


@router.post("/delivered")
async def record_delivery(
    body: DeliveredMessage,
    session: AsyncSession = Depends(get_session),
):
    """Called by encrypt-pipe AFTER it has written the encrypted blob to
    the mailstore — registers the message in the metadata DB so the API
    can list it for IMAP/webmail."""
    res = await session.execute(select(Account).where(Account.email == body.rcpt))
    account = res.scalar_one_or_none()
    if not account:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rcpt not found")

    res = await session.execute(
        select(Folder).where(
            Folder.account_id == account.id,
            Folder.name == body.folder,
        )
    )
    folder = res.scalar_one_or_none()
    if not folder:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "folder not found")

    msg = Message(
        id=uuid.uuid4(),
        account_id=account.id,
        folder_id=folder.id,
        storage_path=body.storage_path,
        size_bytes=body.size_bytes,
        received_at=datetime.now(timezone.utc),
        flags=[],
        encrypted_preview=base64.b64decode(body.encrypted_preview_b64)
            if body.encrypted_preview_b64 else None,
    )
    session.add(msg)
    await session.commit()
    try:
        redis_client = await get_redis()
        await stats.incr(redis_client, stats.SCOPE_MSG_RX)
    except Exception:
        pass
    return {"ok": True, "message_id": str(msg.id)}
