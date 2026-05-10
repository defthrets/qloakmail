"""Privacy helpers — keep raw client IPs out of redis keys and logs.

Rate limiting needs a stable per-client identifier or we can't throttle
abusive sources. But storing the raw IP — even in a redis key with a
short TTL — is more retention than the threat model accepts. We HMAC
the IP with a server-side rotation secret instead. Same input → same
output, but the redis key is irreversible without the secret.

The secret rotates on every API restart (random at startup), which means
rate-limit windows reset across restarts. That's a fair trade for keys
that are unrecoverable even if the redis snapshot leaks.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Request

# Rotates on every API process start; the IP -> token mapping is
# unrecoverable once the process exits.
_ROTATION_SECRET: bytes = secrets.token_bytes(32)


def client_token(request: Request) -> str:
    """Return a stable-per-process opaque token for the calling client.

    The token is HMAC-SHA256(secret, client_ip), truncated to 16 hex
    chars. With X-Forwarded-For honoured (uvicorn --proxy-headers),
    request.client.host is the upstream IP behind nginx.
    """
    ip = request.client.host if request.client else "unknown"
    mac = hmac.new(_ROTATION_SECRET, ip.encode("utf-8"), hashlib.sha256).digest()
    return mac[:8].hex()


def rate_limit_key(request: Request, scope: str) -> str:
    return f"rl:{scope}:{client_token(request)}"
