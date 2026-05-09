from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import schemas
from ..db import get_session
from ..deps import current_account
from ..models import Account

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=schemas.MeResponse)
async def me(account: Account = Depends(current_account)):
    return schemas.MeResponse(
        account_id=account.id,
        email=account.email,
        quota_bytes=account.quota_bytes,
        used_bytes=account.used_bytes,
        created_at=account.created_at,
    )


@router.get("/{email}/pubkey", response_model=schemas.PubkeyLookup)
async def lookup_pubkey(
    email: str,
    session: AsyncSession = Depends(get_session),
):
    """Public pubkey directory — anyone can look up an internal user's
    public key to encrypt mail to them. No auth required so external
    senders' encrypt-pipe can use the same endpoint."""
    res = await session.execute(select(Account).where(Account.email == email))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such account")
    return schemas.PubkeyLookup(
        email=account.email,
        pubkey_armored=account.pubkey_armored,
        pubkey_fpr=account.pubkey_fpr,
    )
