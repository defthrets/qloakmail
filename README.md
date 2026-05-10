# VoidMail

> Zero-access encrypted email. Working name — replace before public launch.

VoidMail is a small-scale, privacy-focused mail platform inspired by Proton Mail.
The server stores **only ciphertext**: incoming mail is encrypted with the
recipient's public key before it touches the mailstore, and the user's private
key is held server-side **only as an Argon2id-encrypted blob** that the server
cannot decrypt.

This README is the operator's guide. End-user docs live in the webmail.

---

## Architecture

```
   Internet
      │  port 25
      ▼
  ┌─────────┐    LMTP    ┌──────────────┐    LMTP    ┌─────────┐
  │ Postfix │ ─────────► │ encrypt-pipe │ ─────────► │ Dovecot │
  │ (MTA)   │            │  (Python)    │            │ (IMAP)  │
  └─────────┘            └──────┬───────┘            └─────────┘
      ▲                         │ pubkey lookup
      │ DKIM                    ▼
      │                  ┌─────────────┐
      │                  │   FastAPI   │ ──► PostgreSQL (users, pubkeys, metadata)
      │                  │   (auth)    │ ──► Redis      (sessions, rate limit)
      │                  └──────┬──────┘
      │                         │
  Rspamd ──────► spam scoring   │ HTTPS
  + outbound rate limit         ▼
                          ┌──────────┐
                          │  Nginx   │ ──► / (webmail SPA, OpenPGP.js + SRP)
                          │  (TLS)   │ ──► /api (FastAPI)
                          └──────────┘
```

**Crypto model:**

* Signup — client generates an OpenPGP keypair. The private key is encrypted
  with a key derived from the user's password via **Argon2id** (and again with
  the recovery code). Server stores: public key (plaintext), encrypted private
  key blob, SRP salt and verifier, recovery-code-encrypted private key blob.
* Login — **SRP-6a**. The password never crosses the wire and the server
  never sees a verifier-equivalent. On success, the client receives the
  encrypted private key blob and decrypts it locally.
* Inbound — Postfix → encrypt-pipe → Dovecot. The pipe wraps the message in
  RFC 3156 `multipart/encrypted` using the recipient's public key.
* Outbound — webmail composes, encrypts to the recipient public key for
  internal mail, or sends plaintext (DKIM-signed) for external mail.
* Search — never hits the server. The client builds a local IndexedDB index
  of the decrypted plaintext.

There is **no password reset**. The recovery code shown at signup is the only
fallback. Lose both → account is unrecoverable by design.

---

## Quick start (local dev)

```bash
cp .env.example .env
# edit .env — at minimum set API_SECRET_KEY and INTERNAL_API_TOKEN

# Generate a DKIM keypair for the dev domain:
./scripts/generate-dkim.sh voidmail.local mail

# Build & start:
docker compose build
docker compose up -d

# Verify:
docker compose ps
curl http://localhost:8080/api/v1/health
# → {"status":"ok"}
```

Open the webmail at <http://localhost:8080/>.

To inject a test message into the encryption pipe (skips the public internet):

```bash
./scripts/inject-test-mail.sh alice@voidmail.local 'Hello' 'Test body'
```

---

## Production deployment

The production target is **FlokiNET Iceland + Njalla registrar + Monero
payment + Tor onion service**. The full step-by-step is in
[docs/deploy-flokinet.md](docs/deploy-flokinet.md). High level:

1. Buy XMR non-KYC; register a domain at Njalla; order a FlokiNET
   Iceland VPS — all payable in Monero, no ID required.
2. Set rDNS on the VPS IP to `mx.<yourdomain>` (FlokiNET does this
   from a support ticket).
3. SSH in and paste the bootstrap script from the deploy doc — it
   installs Docker, sets volatile journald, opens UFW, clones this
   repo, generates a fresh `.env` with strong random secrets, and
   brings the stack up.
4. Add MX / A / AAAA / SPF / DKIM / DMARC at Njalla.
5. Issue a Let's Encrypt cert via the bundled certbot service.
6. Tor publishes the .onion address ~60s after first boot; pull it
   from `docker compose logs tor`.

---

## Repository layout

```
voidmail/
├── docker-compose.yml
├── .env.example
├── api/                  FastAPI service (auth, key store, mail metadata)
├── web/                  Vanilla-JS SPA (OpenPGP.js, SRP-6a client)
├── postfix/              Postfix MTA + Python encrypt-pipe LMTP filter
├── dovecot/              IMAP server config
├── rspamd/               Spam filter + outbound rate limiting
├── nginx/                Reverse proxy (TLS, SPA, /api)
├── postgres/             SQL schema bootstrap
└── scripts/              DKIM gen, DNS helper, test-mail injector
```

---

## Anti-abuse

* **Captcha** at signup — ALTCHA (default; no Google) or Cloudflare Turnstile.
* **Invite codes** for the launch phase — `INVITE_CODES` in `.env`.
* **Rspamd outbound rate limits** — per-account limits set in
  `rspamd/local.d/ratelimit.conf`. Default: 50/hour, 200/day, hard cap 1000/day.
* **Abuse endpoint** — `POST /api/v1/abuse/report`.
* **IP blocklist** at signup — Spamhaus DROP list, refreshed daily.

---

## Security threat model

VoidMail protects against:

* **Server-side mail-content disclosure.** The server only ever holds
  ciphertext — the encrypt-pipe wraps every inbound RFC822 message in
  RFC 3156 multipart/encrypted before it touches the mailstore.
* **Password disclosure.** SRP-6a authentication; the server holds the
  verifier only and the password never crosses the wire.
* **Private-key disclosure.** The server holds private keys only as
  Argon2id-AES-GCM-encrypted blobs that the server cannot derive the
  key for.
* **User-IP correlation by us.** No API access logs, rate-limit keys
  are HMAC(IP) with a per-process secret, sessions table holds no IP
  or user-agent, systemd journal is volatile (RAM, lost on reboot),
  bash history disabled, wtmp/lastlog/btmp linked to /dev/null. See
  the "what we don't log" matrix in
  [docs/deploy-flokinet.md](docs/deploy-flokinet.md).
* **User-IP correlation by anyone.** A built-in Tor v3 hidden service
  is exposed in `docker-compose.yml`. Clients that connect via the
  .onion never reveal a clearnet IP to us *or* our host.

VoidMail does **not** protect against:

* **Active server compromise injecting malicious JS into the SPA.** An
  attacker who controls the API can serve a backdoored OpenPGP.js. Pin
  the script hashes via SRI if you can; high-threat users should use a
  desktop OpenPGP client and treat the SPA as untrusted UI.
* **Metadata leakage.** The SMTP envelope (From / To / received-at /
  message size) is read by Postfix to route the message — no MTA can
  hide this. The encryption pipe writes a fixed `Subject: [encrypted]`
  on the outer envelope and encrypts the original Subject inside the
  PGP body, so internal observers see only the routing minimum.
* **Endpoint compromise.** If the user's device is owned, the attacker
  has the keys. There is no server-side fix for this.
* **Court orders.** No host has a "no-log" policy in any meaningful
  sense. The defense is *not collecting things in the first place* —
  which is what the privacy-hardening above does. There is nothing
  for a subpoena to compel us to hand over except encrypted blobs.

---

## License

TBD before public release.
