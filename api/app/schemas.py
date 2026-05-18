from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Optional

import re

from pydantic import AfterValidator, BaseModel, Field

# Pragmatic email regex. We DON'T use email_validator's EmailStr because
# its 2.x line hard-bans special-use TLDs (.local, .test, .example) which
# breaks dev and any operator running on internal-only domains. The mail
# stack itself enforces domain whitelisting via VOIDMAIL_DOMAIN.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$"
)


def _valid_email(v: str) -> str:
    v = v.strip()
    if len(v) > 254 or not _EMAIL_RE.match(v):
        raise ValueError("not a valid email address")
    return v.lower()


EmailStr = Annotated[str, AfterValidator(_valid_email)]


# ---------- registration ----------


class Argon2Params(BaseModel):
    """Parameters used by the client to derive the symmetric key that
    encrypts the OpenPGP private key. Stored verbatim and returned to
    the client at login time so it can re-derive."""
    type: str = Field(default="argon2id")
    memory_kib: int = Field(default=65536, ge=8192, le=1048576)
    iterations: int = Field(default=3, ge=1, le=20)
    parallelism: int = Field(default=1, ge=1, le=8)
    salt_b64: str   # 16+ bytes base64


class RegisterRequest(BaseModel):
    email: EmailStr
    # SRP - hex-encoded
    srp_salt: str
    srp_verifier: str
    # OpenPGP keys
    pubkey_armored: str
    pubkey_fpr: str
    encrypted_privkey_password: str   # base64
    encrypted_privkey_recovery: str   # base64
    argon2_params: Argon2Params
    # anti-abuse
    invite_code: Optional[str] = None
    captcha_token: Optional[str] = None


class RegisterResponse(BaseModel):
    account_id: uuid.UUID
    email: EmailStr


# ---------- login ----------


class LoginInitRequest(BaseModel):
    email: EmailStr


class LoginInitResponse(BaseModel):
    session_id: str
    srp_salt: str        # hex
    srp_B: str           # hex
    argon2_params: Argon2Params


class LoginVerifyRequest(BaseModel):
    session_id: str
    srp_A: str           # hex
    srp_M1: str          # hex


class LoginVerifyResponse(BaseModel):
    session_token: str
    srp_M2: str          # hex
    account_id: uuid.UUID
    email: EmailStr
    pubkey_armored: str
    encrypted_privkey_password: str   # base64
    argon2_params: Argon2Params


class RecoveryLoginRequest(BaseModel):
    """Login via recovery code returns the recovery-encrypted privkey
    blob, which the client decrypts with Argon2id(recovery_code).
    The client then immediately rewraps the key with a new password
    via /auth/reset-password.
    """
    email: EmailStr
    captcha_token: Optional[str] = None


class RecoveryLoginResponse(BaseModel):
    encrypted_privkey_recovery: str   # base64
    argon2_params: Argon2Params
    pubkey_armored: str
    recovery_token: str               # one-time token for /auth/reset-password


# ---------- account ----------


class MeResponse(BaseModel):
    account_id: uuid.UUID
    email: EmailStr
    quota_bytes: int
    used_bytes: int
    created_at: datetime
    is_admin: bool = False


class PubkeyLookup(BaseModel):
    email: EmailStr
    pubkey_armored: str
    pubkey_fpr: str


# ---------- mail ----------


class FolderOut(BaseModel):
    id: uuid.UUID
    name: str
    system_kind: Optional[str]
    unread_count: int
    total_count: int


class MessageSummary(BaseModel):
    id: uuid.UUID
    folder_id: uuid.UUID
    received_at: datetime
    size_bytes: int
    flags: list[str]
    encrypted_preview_b64: Optional[str]


class MessageBody(BaseModel):
    id: uuid.UUID
    storage_path: str
    received_at: datetime
    size_bytes: int
    flags: list[str]
    # Full RFC 3156 multipart/encrypted blob, base64 of raw bytes.
    encrypted_blob_b64: str


class SendRequest(BaseModel):
    """The client has already encrypted+signed the message for internal
    recipients. For external recipients the client passes a raw RFC822
    body and the server signs with DKIM and relays."""
    rfc822_b64: str
    rcpt_to: list[EmailStr]
    is_internal_only: bool = False


class SendResponse(BaseModel):
    accepted: list[EmailStr]
    rejected: list[EmailStr]


class AbuseReportRequest(BaseModel):
    reported_email: Optional[EmailStr] = None
    reporter_email: Optional[EmailStr] = None
    body: str
    headers: Optional[str] = None


# ---------- internal ----------


class InternalPubkeyResponse(BaseModel):
    """Used by the encrypt-pipe to look up a recipient's public key."""
    email: EmailStr
    pubkey_armored: str
    pubkey_fpr: str
