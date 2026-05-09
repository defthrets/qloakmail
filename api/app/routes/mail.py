from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import schemas
from ..db import get_session
from ..deps import current_account
from ..models import Account, Folder, Message

router = APIRouter(prefix="/mail", tags=["mail"])

# Mailstore root inside the api container — same volume mounted into dovecot
# at /var/mail. We store pre-encrypted blobs as files indexed by storage_path.
MAILSTORE_ROOT = Path(os.environ.get("MAILSTORE_PATH", "/var/mail"))


def _user_dir(email: str) -> Path:
    local, _, domain = email.partition("@")
    return MAILSTORE_ROOT / domain / local / "Maildir" / "cur"


@router.get("/folders", response_model=list[schemas.FolderOut])
async def list_folders(
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    res = await session.execute(select(Folder).where(Folder.account_id == account.id))
    folders = res.scalars().all()
    out: list[schemas.FolderOut] = []
    for f in folders:
        total = await session.scalar(
            select(func.count(Message.id)).where(Message.folder_id == f.id)
        )
        unread = await session.scalar(
            select(func.count(Message.id)).where(
                Message.folder_id == f.id,
                ~Message.flags.any("\\Seen"),
            )
        )
        out.append(schemas.FolderOut(
            id=f.id, name=f.name, system_kind=f.system_kind,
            total_count=int(total or 0), unread_count=int(unread or 0),
        ))
    return out


@router.get("/folders/{folder_id}/messages", response_model=list[schemas.MessageSummary])
async def list_messages(
    folder_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    res = await session.execute(
        select(Folder).where(Folder.id == folder_id, Folder.account_id == account.id)
    )
    if not res.scalar_one_or_none():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "folder not found")

    res = await session.execute(
        select(Message)
        .where(Message.folder_id == folder_id, Message.account_id == account.id)
        .order_by(Message.received_at.desc())
        .limit(min(limit, 200))
        .offset(offset)
    )
    return [
        schemas.MessageSummary(
            id=m.id,
            folder_id=m.folder_id,
            received_at=m.received_at,
            size_bytes=m.size_bytes,
            flags=m.flags,
            encrypted_preview_b64=base64.b64encode(m.encrypted_preview).decode()
                                  if m.encrypted_preview else None,
        )
        for m in res.scalars().all()
    ]


@router.get("/messages/{message_id}", response_model=schemas.MessageBody)
async def get_message(
    message_id: uuid.UUID,
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    res = await session.execute(
        select(Message).where(Message.id == message_id, Message.account_id == account.id)
    )
    msg = res.scalar_one_or_none()
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")

    blob_path = MAILSTORE_ROOT / msg.storage_path
    try:
        blob = blob_path.read_bytes()
    except FileNotFoundError:
        raise HTTPException(status.HTTP_410_GONE, "message blob missing")

    return schemas.MessageBody(
        id=msg.id,
        storage_path=msg.storage_path,
        received_at=msg.received_at,
        size_bytes=msg.size_bytes,
        flags=msg.flags,
        encrypted_blob_b64=base64.b64encode(blob).decode(),
    )


@router.delete("/messages/{message_id}")
async def delete_message(
    message_id: uuid.UUID,
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    res = await session.execute(
        select(Message).where(Message.id == message_id, Message.account_id == account.id)
    )
    msg = res.scalar_one_or_none()
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")
    try:
        (MAILSTORE_ROOT / msg.storage_path).unlink(missing_ok=True)
    except OSError:
        pass
    await session.delete(msg)
    await session.commit()
    return {"ok": True}


@router.post("/send", response_model=schemas.SendResponse)
async def send_message(
    req: schemas.SendRequest,
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    """Hand a (DKIM-signable) RFC822 message to Postfix for relay.

    For internal-only sends the body is already PGP-encrypted client-side.
    For external sends the body is plaintext (PGP if the user attached a
    cert, otherwise cleartext) and Postfix signs with the domain DKIM key.

    Both go through the same submission path so outbound rate-limiting,
    headers, and signing are uniform.
    """
    import smtplib
    from email.message import Message as PyMessage

    raw = base64.b64decode(req.rfc822_b64)
    accepted: list[str] = []
    rejected: list[str] = []

    # Submit via Postfix's submission service inside the network. The
    # postfix container exposes 587 internally; we relay there.
    try:
        with smtplib.SMTP("postfix", 587, timeout=15) as smtp:
            smtp.ehlo()
            for rcpt in req.rcpt_to:
                try:
                    smtp.sendmail(account.email, [str(rcpt)], raw)
                    accepted.append(str(rcpt))
                except smtplib.SMTPRecipientsRefused:
                    rejected.append(str(rcpt))
    except OSError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"submission failed: {e}")

    return schemas.SendResponse(accepted=accepted, rejected=rejected)


@router.post("/messages/{message_id}/flags")
async def update_flags(
    message_id: uuid.UUID,
    body: dict,
    account: Account = Depends(current_account),
    session: AsyncSession = Depends(get_session),
):
    add: list[str] = body.get("add", [])
    remove: list[str] = body.get("remove", [])
    res = await session.execute(
        select(Message).where(Message.id == message_id, Message.account_id == account.id)
    )
    msg = res.scalar_one_or_none()
    if not msg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")
    flags = set(msg.flags or [])
    flags.update(add)
    flags.difference_update(remove)
    msg.flags = sorted(flags)
    await session.commit()
    return {"flags": msg.flags}
