"""Captcha verification — ALTCHA or Cloudflare Turnstile.

Both providers verify by POSTing the client-supplied token to an HTTPS
endpoint. ALTCHA can also be self-hosted; Turnstile is Cloudflare-hosted.

In dev set CAPTCHA_PROVIDER=none to skip verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx

from ..config import get_settings


async def verify_captcha(token: str | None) -> bool:
    s = get_settings()
    provider = (s.captcha_provider or "none").lower()
    if provider == "none":
        return True
    if not token:
        return False
    if provider == "turnstile":
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": s.captcha_secret, "response": token},
            )
            return bool(r.json().get("success"))
    if provider == "altcha":
        # ALTCHA: token is base64(JSON{algorithm, challenge, salt, signature, number}).
        # Verify locally: HMAC(salt|number, secret) == signature, and SHA256(salt+number) == challenge.
        try:
            raw = json.loads(base64.b64decode(token))
            salt = raw["salt"].encode()
            number = str(raw["number"]).encode()
            challenge = raw["challenge"]
            signature = raw["signature"]
            expected_chal = hashlib.sha256(salt + number).hexdigest()
            if not hmac.compare_digest(expected_chal, challenge):
                return False
            expected_sig = hmac.new(s.captcha_secret.encode(), challenge.encode(),
                                    hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_sig, signature)
        except Exception:
            return False
    return False
