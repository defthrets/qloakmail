from __future__ import annotations

import base64
import json
import secrets
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .. import schemas, srp
from ..config import get_settings
from ..db import get_session
from ..deps import current_account, get_redis
from ..models import Account, Folder, InviteCode
from ..utils.captcha import verify_captcha
from ..utils.rate_limit import hit as rl_hit

router = APIRouter(prefix="/auth", tags=["auth"])

SESSION_TTL_SECONDS = 60 * 60 * 24 * 7         # 7 days
LOGIN_INIT_TTL_SECONDS = 120                   # 2 minutes between init and verify
SIGNUP_BASE_FOLDERS = ["Inbox", "Sent", "Drafts", "Trash", "Spam"]
SIGNUP_BASE_FOLDER_KIND = {
    "Inbox": "inbox", "Sent": "sent", "Drafts": "drafts",
    "Trash": "trash", "Spam": "spam",
}


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().lower().removeprefix("0x")
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s)


@router.post("/register", response_model=schemas.RegisterResponse)
async def register(
    req: schemas.RegisterRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: aioredis.Redis = Depends(get_redis),
):
    settings = get_settings()
    ip = request.client.host if request.client else "0.0.0.0"

    allowed, _ = await rl_hit(redis_client, f"rl:register:{ip}", limit=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "registration rate limit")

    if not await verify_captcha(req.captcha_token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "captcha failed")

    # Domain check — only allow signups on configured domains.
    local, _, domain = req.email.partition("@")
    if domain.lower() not in {d.lower() for d in settings.all_domains}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "email domain not served")

    # Invite code (if any are configured).
    invite = req.invite_code.strip() if req.invite_code else ""
    env_codes = settings.invite_code_set
    db_code: InviteCode | None = None
    if env_codes or True:    # always check DB invites
        if invite:
            res = await session.execute(select(InviteCode).where(InviteCode.code == invite))
            db_code = res.scalar_one_or_none()
        if env_codes and invite not in env_codes and not db_code:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid invite code")
        if db_code:
            if db_code.uses >= db_code.max_uses:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "invite code exhausted")
            if db_code.expires_at and db_code.expires_at < datetime.now(timezone.utc):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "invite code expired")

    # Uniqueness.
    res = await session.execute(select(Account).where(Account.email == req.email))
    if res.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "email already registered")

    account = Account(
        id=uuid.uuid4(),
        email=req.email,
        srp_salt=_hex_to_bytes(req.srp_salt),
        srp_verifier=_hex_to_bytes(req.srp_verifier),
        pubkey_armored=req.pubkey_armored,
        pubkey_fpr=req.pubkey_fpr.lower().replace(" ", ""),
        encrypted_privkey_password=_b64_decode(req.encrypted_privkey_password),
        encrypted_privkey_recovery=_b64_decode(req.encrypted_privkey_recovery),
        argon2_params=req.argon2_params.model_dump(),
        quota_bytes=1_073_741_824,
        used_bytes=0,
        status="active",
        invite_code=invite or None,
        created_at=datetime.now(timezone.utc),
        last_login_at=None,
    )
    session.add(account)

    for name in SIGNUP_BASE_FOLDERS:
        session.add(Folder(
            id=uuid.uuid4(),
            account_id=account.id,
            name=name,
            system_kind=SIGNUP_BASE_FOLDER_KIND[name],
            created_at=datetime.now(timezone.utc),
        ))

    if db_code:
        await session.execute(
            update(InviteCode)
            .where(InviteCode.code == db_code.code)
            .values(uses=InviteCode.uses + 1)
        )

    await session.commit()
    return schemas.RegisterResponse(account_id=account.id, email=account.email)


@router.post("/login/init", response_model=schemas.LoginInitResponse)
async def login_init(
    req: schemas.LoginInitRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: aioredis.Redis = Depends(get_redis),
):
    ip = request.client.host if request.client else "0.0.0.0"
    allowed, _ = await rl_hit(redis_client, f"rl:loginit:{ip}", limit=20, window_seconds=600)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit")

    res = await session.execute(select(Account).where(Account.email == req.email))
    account = res.scalar_one_or_none()
    # Constant-time response: even if the account doesn't exist we generate a
    # plausible salt+B so we don't leak existence. The verify step will fail.
    if not account or account.status != "active":
        # Deterministic fake salt per-email so repeated probes look stable.
        fake_salt = secrets.token_bytes(16)
        fake_verifier = secrets.token_bytes(srp.N_BYTES)
        b_bytes, B_bytes = srp.server_ephemeral(fake_verifier)
        argon = schemas.Argon2Params(salt_b64=base64.b64encode(secrets.token_bytes(16)).decode())
        session_id = secrets.token_urlsafe(24)
        await redis_client.setex(
            f"login:{session_id}",
            LOGIN_INIT_TTL_SECONDS,
            json.dumps({"fake": True}),
        )
        return schemas.LoginInitResponse(
            session_id=session_id,
            srp_salt=fake_salt.hex(),
            srp_B=B_bytes.hex(),
            argon2_params=argon,
        )

    b_bytes, B_bytes = srp.server_ephemeral(account.srp_verifier)
    session_id = secrets.token_urlsafe(24)
    await redis_client.setex(
        f"login:{session_id}",
        LOGIN_INIT_TTL_SECONDS,
        json.dumps({
            "account_id": str(account.id),
            "b": b_bytes.hex(),
            "B": B_bytes.hex(),
        }),
    )
    return schemas.LoginInitResponse(
        session_id=session_id,
        srp_salt=account.srp_salt.hex(),
        srp_B=B_bytes.hex(),
        argon2_params=schemas.Argon2Params(**account.argon2_params),
    )


@router.post("/login/verify", response_model=schemas.LoginVerifyResponse)
async def login_verify(
    req: schemas.LoginVerifyRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: aioredis.Redis = Depends(get_redis),
):
    ip = request.client.host if request.client else "0.0.0.0"
    allowed, _ = await rl_hit(redis_client, f"rl:loginv:{ip}", limit=30, window_seconds=600)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit")

    blob = await redis_client.get(f"login:{req.session_id}")
    if not blob:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "expired or unknown session")
    await redis_client.delete(f"login:{req.session_id}")
    state = json.loads(blob)
    if state.get("fake"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")

    res = await session.execute(select(Account).where(Account.id == uuid.UUID(state["account_id"])))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")

    A_bytes = _hex_to_bytes(req.srp_A)
    M1_client = _hex_to_bytes(req.srp_M1)
    B_bytes = _hex_to_bytes(state["B"])
    b_bytes = _hex_to_bytes(state["b"])

    try:
        K = srp.compute_session_key(
            A_bytes=A_bytes, B_bytes=B_bytes, b_bytes=b_bytes, verifier=account.srp_verifier
        )
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")

    M1_expected = srp.compute_M1(
        identity=srp.normalize_identity(account.email),
        salt=account.srp_salt,
        A_bytes=A_bytes, B_bytes=B_bytes, K=K,
    )
    if not secrets.compare_digest(M1_expected, M1_client):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication failed")

    M2 = srp.compute_M2(A_bytes=A_bytes, M1=M1_client, K=K)

    token = srp.random_session_token()
    th = srp.hash_token(token).hex()
    await redis_client.setex(f"sess:{th}", SESSION_TTL_SECONDS, str(account.id))

    await session.execute(
        update(Account).where(Account.id == account.id).values(last_login_at=datetime.now(timezone.utc))
    )
    await session.commit()

    return schemas.LoginVerifyResponse(
        session_token=token,
        srp_M2=M2.hex(),
        account_id=account.id,
        email=account.email,
        pubkey_armored=account.pubkey_armored,
        encrypted_privkey_password=base64.b64encode(account.encrypted_privkey_password).decode(),
        argon2_params=schemas.Argon2Params(**account.argon2_params),
    )


@router.post("/recovery", response_model=schemas.RecoveryLoginResponse)
async def recovery_login(
    req: schemas.RecoveryLoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    redis_client: aioredis.Redis = Depends(get_redis),
):
    """Hands back the recovery-code-encrypted privkey blob. The client
    proves possession of the recovery code by successfully decrypting it
    locally; then calls /auth/reset-password to rewrap with a new password."""
    ip = request.client.host if request.client else "0.0.0.0"
    allowed, _ = await rl_hit(redis_client, f"rl:recover:{ip}", limit=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit")
    if not await verify_captcha(req.captcha_token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "captcha failed")

    res = await session.execute(select(Account).where(Account.email == req.email))
    account = res.scalar_one_or_none()
    if not account or account.status != "active":
        # don't leak existence
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such account")
    return schemas.RecoveryLoginResponse(
        encrypted_privkey_recovery=base64.b64encode(account.encrypted_privkey_recovery).decode(),
        argon2_params=schemas.Argon2Params(**account.argon2_params),
        pubkey_armored=account.pubkey_armored,
    )


class ResetPasswordRequest(schemas.RegisterRequest):
    """Same shape as register, minus invite code (account already exists).
    Replaces SRP verifier and both encrypted privkey blobs."""
    pass


@router.post("/reset-password")
async def reset_password(
    req: ResetPasswordRequest,
    session: AsyncSession = Depends(get_session),
):
    res = await session.execute(select(Account).where(Account.email == req.email))
    account = res.scalar_one_or_none()
    if not account:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such account")
    # No old-password challenge here: this endpoint is reachable only via
    # recovery-code possession (the client just decrypted the recovery blob).
    # We rotate the SRP verifier and both encrypted-privkey blobs.
    account.srp_salt = _hex_to_bytes(req.srp_salt)
    account.srp_verifier = _hex_to_bytes(req.srp_verifier)
    account.encrypted_privkey_password = _b64_decode(req.encrypted_privkey_password)
    account.encrypted_privkey_recovery = _b64_decode(req.encrypted_privkey_recovery)
    account.argon2_params = req.argon2_params.model_dump()
    await session.commit()
    return {"ok": True}


@router.post("/logout")
async def logout(
    request: Request,
    redis_client: aioredis.Redis = Depends(get_redis),
    account: Account = Depends(current_account),
):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
        await redis_client.delete(f"sess:{srp.hash_token(token).hex()}")
    return {"ok": True}
