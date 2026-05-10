"""Round-trip the latest message: login, list inbox, fetch encrypted
blob, decrypt with the user's private key, print plaintext."""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys

import httpx
import pgpy

# Reuse the helpers from smoke_register.
sys.path.insert(0, os.path.dirname(__file__))
from smoke_register import srp_login, unwrap_privkey


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    args = ap.parse_args()

    api = args.api.rstrip("/")
    client = httpx.Client(timeout=30)

    # Login
    init = client.post(f"{api}/api/v1/auth/login/init",
                       json={"email": args.email}).raise_for_status().json()
    A, M1, _, _ = srp_login(
        args.email, args.password,
        bytes.fromhex(init["srp_salt"]), bytes.fromhex(init["srp_B"]),
    )
    v = client.post(f"{api}/api/v1/auth/login/verify", json={
        "session_id": init["session_id"],
        "srp_A": A.hex(),
        "srp_M1": M1.hex(),
    }).raise_for_status().json()
    token = v["session_token"]
    privkey_armored = unwrap_privkey(
        v["encrypted_privkey_password"], args.password, v["argon2_params"]
    )
    privkey, _ = pgpy.PGPKey.from_blob(privkey_armored)
    print(f"[+] login ok, decrypted privkey fpr={privkey.fingerprint!s}")

    auth = {"Authorization": f"Bearer {token}"}

    folders = client.get(f"{api}/api/v1/mail/folders", headers=auth).raise_for_status().json()
    inbox = next(f for f in folders if f["system_kind"] == "inbox")
    print(f"[+] inbox folder: {inbox['id']} ({inbox['total_count']} msgs)")

    msgs = client.get(f"{api}/api/v1/mail/folders/{inbox['id']}/messages",
                      headers=auth).raise_for_status().json()
    if not msgs:
        print("[-] no messages in inbox", file=sys.stderr); sys.exit(2)
    msg = msgs[0]
    print(f"[+] latest message: {msg['id']} ({msg['size_bytes']} bytes)")

    body = client.get(f"{api}/api/v1/mail/messages/{msg['id']}",
                      headers=auth).raise_for_status().json()
    blob = base64.b64decode(body["encrypted_blob_b64"]).decode("utf-8", "replace")

    # Pull the PGP MESSAGE block out of the multipart/encrypted envelope.
    m = re.search(r"-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----", blob)
    assert m, "no PGP block in fetched blob"
    pgp_msg = pgpy.PGPMessage.from_blob(m.group(0))
    decrypted = privkey.decrypt(pgp_msg)
    plaintext = decrypted.message
    if isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode("utf-8", "replace")

    print("=" * 60)
    print("DECRYPTED RFC822:")
    print("=" * 60)
    print(plaintext)
    print("=" * 60)


if __name__ == "__main__":
    main()
