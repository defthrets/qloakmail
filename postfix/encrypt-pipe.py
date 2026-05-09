"""VoidMail encryption pipe.

A tiny LMTP server that sits between Postfix (after spam filtering) and
the on-disk mailstore. For each delivery:

    1. Look up the recipient's OpenPGP public key via the internal API.
    2. Wrap the entire RFC822 message in an RFC 3156 multipart/encrypted
       PGP envelope encrypted to that public key.
    3. Write the resulting blob to the recipient's Maildir/cur as a
       single file (the same volume Dovecot reads from).
    4. POST a metadata record to the API so the webmail/IMAP layer can
       list it.

The plaintext body is held in memory only for as long as it takes to
encrypt; nothing plaintext ever touches disk on this server.

Postfix talks to this server over LMTP on port 10025 (configured via
master.cf). The recipient address is taken from the LMTP RCPT TO.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from pathlib import Path
from typing import Optional

import httpx
import pgpy
from aiosmtpd.controller import Controller
from aiosmtpd.lmtp import LMTP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s encrypt-pipe %(levelname)s %(message)s",
)
log = logging.getLogger("encrypt-pipe")

INTERNAL_API_URL = os.environ.get("INTERNAL_API_URL", "http://api:8000").rstrip("/")
INTERNAL_API_TOKEN = os.environ["INTERNAL_API_TOKEN"]
MAILSTORE_ROOT = Path(os.environ.get("MAILSTORE_PATH", "/var/mail"))
BIND_HOST, BIND_PORT = os.environ.get("ENCRYPT_PIPE_BIND", "0.0.0.0:10025").split(":")
BIND_PORT = int(BIND_PORT)
DOMAINS = {d.strip().lower() for d in os.environ.get(
    "VOIDMAIL_DOMAIN", "voidmail.local"
).split(",")}
extra = os.environ.get("VOIDMAIL_EXTRA_DOMAINS", "")
if extra:
    DOMAINS.update(d.strip().lower() for d in extra.split(",") if d.strip())


_pubkey_cache: dict[str, tuple[float, pgpy.PGPKey]] = {}
_PUBKEY_TTL = 300.0


async def _fetch_pubkey(client: httpx.AsyncClient, email: str) -> Optional[pgpy.PGPKey]:
    cached = _pubkey_cache.get(email)
    if cached and cached[0] > time.time():
        return cached[1]
    try:
        r = await client.get(
            f"{INTERNAL_API_URL}/api/v1/internal/pubkey/{email}",
            headers={"X-Internal-Token": INTERNAL_API_TOKEN},
            timeout=8.0,
        )
        if r.status_code != 200:
            log.warning("pubkey lookup %s -> %s", email, r.status_code)
            return None
        armored = r.json()["pubkey_armored"]
        key, _ = pgpy.PGPKey.from_blob(armored)
        _pubkey_cache[email] = (time.time() + _PUBKEY_TTL, key)
        return key
    except Exception as e:
        log.exception("pubkey lookup failed: %s", e)
        return None


def _encrypt_to_pgpmime(raw_rfc822: bytes, pubkey: pgpy.PGPKey) -> bytes:
    """Wrap raw_rfc822 as RFC 3156 multipart/encrypted, encrypted to pubkey.

    The plaintext is the *full* RFC822 message including its headers — so
    Subject, From, To and any X-* headers are also hidden from the server.
    The outer envelope keeps only the bare minimum delivery headers
    (From, To, Date, Message-ID) so Dovecot can index and IMAP can list.
    """
    inner = pgpy.PGPMessage.new(raw_rfc822, file=False)
    encrypted = pubkey.encrypt(inner)

    # Pull a few headers from the *inbound* message to reuse on the outer
    # envelope. We deliberately DO NOT copy Subject — that's part of the
    # encrypted body now.
    inbound = message_from_bytes(raw_rfc822, policy=default_policy)
    out = EmailMessage(policy=default_policy)
    out["From"] = inbound.get("From", "unknown@unknown")
    out["To"] = inbound.get("Delivered-To") or inbound.get("To", "")
    out["Date"] = inbound.get("Date", "")
    out["Message-ID"] = inbound.get("Message-ID", f"<{uuid.uuid4()}@voidmail>")
    out["Subject"] = "[encrypted]"
    out["MIME-Version"] = "1.0"
    out.set_type("multipart/encrypted")
    out.set_param("protocol", "application/pgp-encrypted")
    # Use a stable boundary so we can build manually.
    boundary = f"voidmail-pgp-{uuid.uuid4().hex}"
    out.set_boundary(boundary)

    # Two MIME parts: the version marker, then the ciphertext.
    version = EmailMessage(policy=default_policy)
    version.set_type("application/pgp-encrypted")
    version.set_payload("Version: 1\n")

    payload = EmailMessage(policy=default_policy)
    payload.set_type("application/octet-stream")
    payload.add_header("Content-Disposition", "inline", filename="encrypted.asc")
    payload.set_payload(str(encrypted))

    out.attach(version)
    out.attach(payload)
    return out.as_bytes()


def _maildir_for(email: str) -> Path:
    local, _, domain = email.partition("@")
    p = MAILSTORE_ROOT / domain / local / "Maildir"
    for sub in ("new", "cur", "tmp"):
        (p / sub).mkdir(parents=True, exist_ok=True)
    return p


def _maildir_filename(size: int) -> str:
    # Maildir naming: time.Pid.host,S=size:2,
    return f"{int(time.time())}.P{os.getpid()}.voidmail,S={size}"


async def _record_delivery(
    client: httpx.AsyncClient,
    rcpt: str,
    storage_path: str,
    size: int,
) -> None:
    try:
        r = await client.post(
            f"{INTERNAL_API_URL}/api/v1/internal/delivered",
            headers={"X-Internal-Token": INTERNAL_API_TOKEN},
            json={
                "rcpt": rcpt,
                "storage_path": storage_path,
                "size_bytes": size,
                "folder": "Inbox",
            },
            timeout=8.0,
        )
        if r.status_code >= 300:
            log.warning("delivered POST %s -> %s %s", rcpt, r.status_code, r.text)
    except Exception as e:
        log.exception("delivered POST failed: %s", e)


class EncryptHandler:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def handle_DATA(self, server, session, envelope) -> str:
        try:
            for rcpt in envelope.rcpt_tos:
                rcpt_norm = rcpt.lower().strip()
                _, _, domain = rcpt_norm.partition("@")
                if domain not in DOMAINS:
                    log.warning("rcpt not local: %s", rcpt_norm)
                    return f"550 {rcpt} not a local recipient"
                pubkey = await _fetch_pubkey(self.client, rcpt_norm)
                if pubkey is None:
                    return f"550 4.1.1 {rcpt}: no public key"

                raw = envelope.original_content or envelope.content
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", "replace")

                ciphertext = _encrypt_to_pgpmime(raw, pubkey)

                maildir = _maildir_for(rcpt_norm)
                fname = _maildir_filename(len(ciphertext))
                tmp_path = maildir / "tmp" / fname
                final_path = maildir / "new" / fname
                tmp_path.write_bytes(ciphertext)
                tmp_path.rename(final_path)

                rel = final_path.relative_to(MAILSTORE_ROOT).as_posix()
                await _record_delivery(self.client, rcpt_norm, rel, len(ciphertext))
                log.info("delivered to %s as %s (%d bytes)", rcpt_norm, rel, len(ciphertext))
            return "250 2.0.0 Ok"
        except Exception:
            log.exception("delivery failed")
            return "451 4.0.0 internal error"


def _factory(handler):
    def make(*a, **kw):
        return LMTP(handler, *a, **kw)
    return make


def main() -> int:
    handler = EncryptHandler()
    controller = Controller(
        handler,
        hostname=BIND_HOST,
        port=BIND_PORT,
        server_class=LMTP,
        server_kwargs={"enable_SMTPUTF8": True},
    )
    log.info("encrypt-pipe listening on %s:%d (LMTP)", BIND_HOST, BIND_PORT)
    log.info("local domains: %s", ", ".join(sorted(DOMAINS)))
    controller.start()
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_forever()
    except KeyboardInterrupt:
        controller.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
