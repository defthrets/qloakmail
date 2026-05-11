# QloakMail

> Encrypted email we can't read. <https://qloak.me>

QloakMail is a small-scale, privacy-first mail platform built around end-to-end
encryption and zero-access design. The server stores **only ciphertext**:
incoming mail is encrypted with the recipient's public key before it touches
the mailstore, and the user's private key is held server-side **only as an
Argon2id-encrypted blob** that the server cannot decrypt.

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

## What QloakMail is built to protect

* **Mail content is end-to-end encrypted.** The encrypt-pipe wraps every
  inbound RFC822 message in RFC 3156 multipart/encrypted using the
  recipient's public key before it touches the mailstore. Only the
  recipient's device holds the key needed to read it.
* **Passwords stay on your device.** SRP-6a authentication means the
  server only ever sees a verifier — the password itself never crosses
  the wire.
* **Private keys are sealed locally.** The server holds them only as
  Argon2id + AES-GCM blobs derived from your password. Lose the
  password and the recovery code, and the keys are mathematically
  unrecoverable — even by us.
* **No IP correlation by us.** No API access logs, rate-limit keys are
  HMAC(IP) with a per-process secret, the sessions table holds no IP or
  user-agent, the systemd journal is volatile (RAM, lost on reboot),
  bash history is disabled, and wtmp/lastlog/btmp are linked to
  /dev/null. See the "what we don't log" matrix in
  [docs/deploy-flokinet.md](docs/deploy-flokinet.md).
* **No IP correlation by anyone, optionally.** A built-in Tor v3 hidden
  service is exposed in `docker-compose.yml`. Clients that connect via
  the .onion never reveal a clearnet IP — to us or to our host.
* **Search stays local.** The webmail builds an IndexedDB index of
  decrypted plaintext on-device. Search queries never touch the server.
* **Open source.** Audit the code, build it yourself, run your own
  instance.

---

## License

TBD before public release.

---
