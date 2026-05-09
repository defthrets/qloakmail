"""SRP-6a server-side, RFC 5054, 2048-bit group, SHA-256.

The corresponding client lives in web/srp-client.js. The two MUST agree
exactly on:

  * the prime N and generator g (RFC 5054 Appendix A, 2048-bit)
  * the hash function (SHA-256)
  * the byte-padding rules (left-pad every input to len(N) before hashing)
  * the username -> identity binding (we hash lowercased email)

The server NEVER sees the password. Registration takes srp_salt and
srp_verifier from the client; login is a two-step exchange.
"""
from __future__ import annotations

import hashlib
import os
import secrets

# RFC 5054 Appendix A 2048-bit group
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
N_BYTES = (N.bit_length() + 7) // 8  # 256


def _h(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def _to_bytes(n: int, length: int = N_BYTES) -> bytes:
    return n.to_bytes(length, "big")


def _from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _pad(b: bytes) -> bytes:
    if len(b) > N_BYTES:
        raise ValueError("value larger than N")
    return b.rjust(N_BYTES, b"\x00")


# k = H(N | PAD(g))   SRP-6a
_k = _from_bytes(_h(_pad(_to_bytes(N)), _pad(_to_bytes(g))))


def server_ephemeral(verifier: bytes) -> tuple[bytes, bytes]:
    """Generate (b, B). b is private, never leaves the server.
    Returns (b_bytes, B_bytes)."""
    v = _from_bytes(verifier)
    while True:
        b = _from_bytes(secrets.token_bytes(32)) % N
        B = (_k * v + pow(g, b, N)) % N
        if B % N != 0:
            return _to_bytes(b), _to_bytes(B)


def compute_session_key(
    *,
    A_bytes: bytes,
    B_bytes: bytes,
    b_bytes: bytes,
    verifier: bytes,
) -> bytes:
    """Compute the shared session key K on the server side.

    K = H( S )   where  S = (A * v^u) ^ b   mod N
    u = H( PAD(A) | PAD(B) )
    """
    A = _from_bytes(A_bytes) % N
    if A == 0:
        raise ValueError("invalid A")
    u = _from_bytes(_h(_pad(A_bytes), _pad(B_bytes)))
    if u == 0:
        raise ValueError("invalid u")
    v = _from_bytes(verifier)
    b = _from_bytes(b_bytes)
    S = pow(A * pow(v, u, N), b, N)
    return _h(_to_bytes(S))


def compute_M1(*, identity: str, salt: bytes, A_bytes: bytes, B_bytes: bytes, K: bytes) -> bytes:
    """Compute the client proof M1 the same way the client did, so we
    can compare. Standard SRP-6a M1:

        M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
    """
    HN = _h(_to_bytes(N))
    Hg = _h(_to_bytes(g))
    HNxorHg = bytes(a ^ b for a, b in zip(HN, Hg))
    HI = _h(identity.encode("utf-8"))
    return _h(HNxorHg, HI, salt, A_bytes, B_bytes, K)


def compute_M2(*, A_bytes: bytes, M1: bytes, K: bytes) -> bytes:
    """Server proof returned to the client: M2 = H(A | M1 | K)."""
    return _h(A_bytes, M1, K)


def normalize_identity(email: str) -> str:
    return email.strip().lower()


def random_session_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
