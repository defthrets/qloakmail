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

## Deployment to FlokiNET Iceland VPS

1. `apt install docker.io docker-compose-plugin` and clone this repo.
2. Point your domain's `MX`, `A/AAAA` and reverse `PTR` records at the VPS.
   The VPS ISP must let you set the rDNS — FlokiNET does on request.
3. Fill `.env` with the production domain and a strong `API_SECRET_KEY`.
4. Generate DKIM: `./scripts/generate-dkim.sh yourdomain.tld mail`.
5. Print the DNS records you need: `./scripts/dns-records.sh yourdomain.tld`.
6. `docker compose up -d` and obtain certs:
   ```bash
   docker compose run --rm certbot certonly --webroot \
       -w /var/www/certbot -d yourdomain.tld -d mail.yourdomain.tld
   ```

### Required DNS records

The `scripts/dns-records.sh` helper prints these populated for your domain:

| Type   | Name                              | Value                                        |
| ------ | --------------------------------- | -------------------------------------------- |
| A      | `voidmail.tld`                    | `<vps ipv4>`                                 |
| AAAA   | `voidmail.tld`                    | `<vps ipv6>`                                 |
| MX     | `voidmail.tld`                    | `10 mx.voidmail.tld.`                        |
| A      | `mx.voidmail.tld`                 | `<vps ipv4>`                                 |
| PTR    | `<reverse>.in-addr.arpa`          | `mx.voidmail.tld.` (set with VPS provider)   |
| TXT    | `voidmail.tld`                    | `v=spf1 mx -all`                             |
| TXT    | `mail._domainkey.voidmail.tld`    | `v=DKIM1; k=rsa; p=<from generate-dkim.sh>`  |
| TXT    | `_dmarc.voidmail.tld`             | `v=DMARC1; p=quarantine; rua=mailto:dmarc@voidmail.tld; adkim=s; aspf=s` |

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

## Security threat model (summary)

VoidMail protects against:

* Server compromise stealing **plaintext mail** at rest (mail is encrypted to
  the user's public key on delivery).
* Server compromise stealing **passwords** (SRP — server holds verifier only).
* Server compromise stealing **private keys** (only encrypted blobs are stored).

VoidMail does **not** protect against:

* Active server compromise injecting malicious JS into the SPA. Pin the script
  hashes via Subresource Integrity if you can; consider a desktop client for
  high-threat users.
* Metadata leakage — message envelope (From/To/Subject/timestamps for headers
  delivered before encryption) is necessarily server-visible. The pipe encrypts
  the **whole** RFC822 body but the SMTP envelope cannot be hidden from the MTA.
* Endpoint compromise. If the user's device is owned, the attacker has the keys.

---

## License

TBD before public release.
