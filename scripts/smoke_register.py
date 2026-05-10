"""End-to-end smoke test client for QloakMail.

Generates an OpenPGP keypair, computes an SRP-6a verifier, AES-GCM-wraps
the private key with an Argon2id-derived key from the password, and
POSTs to /api/v1/auth/register. Then runs the SRP login round-trip and
unwraps the private key to confirm the server is honest.

Mirrors what the webmail does in JavaScript — useful for smoke tests
that don't need a browser. Run inside the api container so the deps are
already available; or pip install pgpy argon2-cffi httpx.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys

import httpx
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm, KeyFlags, HashAlgorithm,
    SymmetricKeyAlgorithm, CompressionAlgorithm,
)
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ----- SRP-6a (matches api/app/srp.py and web/srp-client.js) -----
N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
N = int(N_HEX, 16)
g = 2
N_BYTES = 256


def _h(*chunks):
    h = hashlib.sha256()
    for c in chunks: h.update(c)
    return h.digest()


def _ib(n, length=N_BYTES): return n.to_bytes(length, "big")
def _bi(b): return int.from_bytes(b, "big")
def _pad(b): return b.rjust(N_BYTES, b"\x00")


_k = _bi(_h(_pad(_ib(N)), _pad(_ib(g))))


def srp_verifier(email: str, password: str):
    salt = secrets.token_bytes(16)
    inner = _h((email.lower() + ":" + password).encode())
    x = _bi(_h(salt, inner))
    v = pow(g, x, N)
    return salt, _ib(v), x


def srp_login(email: str, password: str, salt: bytes, B_bytes: bytes):
    a = _bi(secrets.token_bytes(32)) % N
    A = pow(g, a, N)
    A_bytes = _pad(_ib(A))
    B = _bi(B_bytes)
    if B % N == 0: raise ValueError("invalid B")
    u = _bi(_h(_pad(A_bytes), _pad(B_bytes)))
    inner = _h((email.lower() + ":" + password).encode())
    x = _bi(_h(salt, inner))
    S = pow(B - (_k * pow(g, x, N)) % N, a + u * x, N)
    K = _h(_ib(S))
    HN = _h(_ib(N)); Hg = _h(_ib(g))
    HNxorHg = bytes(p ^ q for p, q in zip(HN, Hg))
    HI = _h(email.lower().encode())
    M1 = _h(HNxorHg, HI, salt, A_bytes, _pad(B_bytes), K)
    M2_expected = _h(A_bytes, M1, K)
    return A_bytes, M1, M2_expected, K


# ----- Argon2id + AES-GCM wrap -----
def derive_key(password: str, params: dict) -> bytes:
    salt = base64.b64decode(params["salt_b64"])
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=params["iterations"],
        memory_cost=params["memory_kib"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID,
    )


def wrap_privkey(privkey_armored: str, password: str, params=None):
    if params is None:
        params = {
            "type": "argon2id",
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 1,
            "salt_b64": base64.b64encode(secrets.token_bytes(16)).decode(),
        }
    key = derive_key(password, params)
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, privkey_armored.encode(), None)
    blob = bytes([1]) + iv + ct
    return {"blobB64": base64.b64encode(blob).decode(), "argon2_params": params}


def unwrap_privkey(blob_b64: str, password: str, params: dict) -> str:
    blob = base64.b64decode(blob_b64)
    assert blob[0] == 1, "bad version"
    iv, ct = blob[1:13], blob[13:]
    key = derive_key(password, params)
    return AESGCM(key).decrypt(iv, ct, None).decode()


# ----- main -----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--api", default=os.environ.get("API", "http://127.0.0.1:8000"))
    ap.add_argument("--register", action="store_true")
    ap.add_argument("--login", action="store_true")
    args = ap.parse_args()

    api = args.api.rstrip("/")
    client = httpx.Client(timeout=30)

    if args.register:
        print(f"[1/4] generating OpenPGP keypair for {args.email}...")
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new(args.email, email=args.email)
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
        )
        priv_armored = str(key)
        pub_armored = str(key.pubkey)
        fpr = str(key.fingerprint).replace(" ", "").lower()

        print("[2/4] computing SRP verifier...")
        salt, verifier, _ = srp_verifier(args.email, args.password)

        print("[3/4] wrapping private key...")
        wp = wrap_privkey(priv_armored, args.password)
        recovery_code = "TESTRECOVERY-" + secrets.token_hex(8).upper()
        wr = wrap_privkey(priv_armored, recovery_code)

        print("[4/4] POST /auth/register...")
        r = client.post(f"{api}/api/v1/auth/register", json={
            "email": args.email,
            "srp_salt": salt.hex(),
            "srp_verifier": verifier.hex(),
            "pubkey_armored": pub_armored,
            "pubkey_fpr": fpr,
            "encrypted_privkey_password": wp["blobB64"],
            "encrypted_privkey_recovery": wr["blobB64"],
            "argon2_params": wp["argon2_params"],
            "captcha_token": None,
        })
        r.raise_for_status()
        print("REGISTERED:", r.json())
        print("RECOVERY CODE (save):", recovery_code)

    if args.login:
        print(f"[1/3] /auth/login/init for {args.email}...")
        r = client.post(f"{api}/api/v1/auth/login/init", json={"email": args.email})
        r.raise_for_status()
        init = r.json()

        print("[2/3] computing SRP A and M1...")
        A, M1, M2_expected, K = srp_login(
            args.email, args.password,
            bytes.fromhex(init["srp_salt"]),
            bytes.fromhex(init["srp_B"]),
        )

        print("[3/3] /auth/login/verify...")
        r = client.post(f"{api}/api/v1/auth/login/verify", json={
            "session_id": init["session_id"],
            "srp_A": A.hex(),
            "srp_M1": M1.hex(),
        })
        r.raise_for_status()
        v = r.json()
        if bytes.fromhex(v["srp_M2"]) != M2_expected:
            print("!! server proof mismatch — possible MITM", file=sys.stderr)
            sys.exit(2)
        print("LOGIN OK. token=" + v["session_token"][:12] + "...")

        # Decrypt the private key blob
        priv = unwrap_privkey(
            v["encrypted_privkey_password"], args.password, v["argon2_params"]
        )
        if priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----"):
            print("PRIVKEY DECRYPT OK (armored).")
        else:
            print("PRIVKEY DECRYPT FAILED (got: %r)" % priv[:60], file=sys.stderr)
            sys.exit(2)

        print("SESSION TOKEN:", v["session_token"])


if __name__ == "__main__":
    main()
