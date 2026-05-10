# Deploying QloakMail to FlokiNET Iceland

This is the production deployment guide. The privacy claim of QloakMail
turns on three things, in order of importance:

1. **The application itself doesn't collect IPs, user agents, or access
   logs.** That's enforced in code — see `api/app/utils/privacy.py`,
   the `--no-access-log` flag in `api/Dockerfile`, and the empty
   `sessions.ip` column in `postgres/init.sql`.
2. **Users can reach us without revealing their clearnet IP**, via the
   built-in Tor hidden service. The .onion address is generated on the
   VPS itself and never leaves it (except via the user-visible URL).
3. **The host operator is in a friendly jurisdiction with a strong
   anti-takedown stance.** That's what this guide is for.

This guide assumes you have **never used FlokiNET, Njalla, or Monero
before** and walks through each. If you already have any of these,
skip the corresponding section.

---

## Step 1 — Acquire Monero (XMR)

Monero is the only practical anonymous payment for both FlokiNET and
Njalla. Cards and bank transfers are accepted but defeat the purpose.

* Buy XMR at a non-KYC venue (LocalMonero, RetoSwap, Haveno, or via a
  swap from BTC purchased non-KYC at an ATM).
* Send to a wallet you control. **Monero GUI** (Linux/Mac/Windows) or
  **Cake Wallet** (mobile) — both run their own daemon or talk to a
  community node.
* Budget: ~0.05 XMR for a year of FlokiNET VPS + Njalla domain at
  current prices. Buy a touch more for fees.

> **Why not just card?** Even if FlokiNET doesn't store the card data,
> the issuing bank logs the merchant. A subpoena to your bank reveals
> "you paid FlokiNET on date X." Monero leaves no such trail.

---

## Step 2 — Register a domain through Njalla

Njalla acts as a privacy proxy: they own the domain in WHOIS, you have
contractual ownership. Iceland-based, takes Monero, no ID required.

1. Go to <https://njal.la> (clearnet) or
   `njallaxxxxxxxxxx.onion` (find current onion via their site).
2. Account: anonymous email + a strong passphrase. They don't ask for
   anything else.
3. **Search a domain.** Recommendations:
   * `.email` — cheap, descriptive, none of the legacy reputation issues.
   * `.is` — Iceland TLD; jurisdiction-aligned, but pricier.
   * `.ch` — Switzerland; also strong privacy laws.
   * Avoid `.com`/`.net` — Verisign / ICANN involvement = US legal pull.
4. Pay in XMR. The address has a 30-min window; if you miss it the order
   cancels and you can retry.
5. Once active, in the Njalla panel: **DNS records** → leave blank for
   now. We'll fill them in after the VPS is up.

> Njalla as registrar means there's nothing in WHOIS that points at you.
> If you also use Njalla for DNS hosting (recommended), DNS query logs
> stay under their privacy policy too.

---

## Step 3 — Order a FlokiNET VPS in Iceland

1. Go to <https://flokinet.is> (also has a `.onion`).
2. Account: anonymous email + passphrase. Like Njalla, no ID.
3. **VPS → Iceland**, pick the smallest plan that fits:
   * **VPS-1**: 1 vCPU / 2 GB / 30 GB / 100 Mbps — €7/mo. Tight but works.
   * **VPS-2**: 2 vCPU / 4 GB / 50 GB / 200 Mbps — €13/mo. **Recommended.**
   * **VPS-3 and up**: only if you'll run >100 users.
4. **OS**: Ubuntu 24.04 LTS (the cloud-init below targets this).
5. **Hostname**: `mx.<yourdomain>` (we'll set rDNS after).
6. **SSH key**: paste your public key — generated locally with
   `ssh-keygen -t ed25519 -f ~/.ssh/voidmail_ed25519`.
7. Pay in XMR.

After provisioning (5–15 min) you receive an IP and root credentials.

> **Why Iceland over Romania/Finland (also FlokiNET locations)?**
> Iceland has the strongest anti-takedown legal regime of the three
> (IMMI), no mandatory data retention, and FlokiNET's Iceland servers
> are in their own racks — not co-located. Romania is a fine fallback
> if Iceland is sold out.

---

## Step 4 — Set rDNS

Email your VPS support ticket (or use the panel if FlokiNET added
rDNS-self-serve recently): "Please set PTR for `<your-IPv4>` to
`mx.<yourdomain>` and PTR for `<your-IPv6>` to the same."

Without this, Gmail and most other big MTAs will reject your inbound
mail with `PTR mismatch`.

---

## Step 5 — Bootstrap the VPS

SSH in:

```bash
ssh -i ~/.ssh/voidmail_ed25519 root@<vps-ip>
```

Once in, run the bootstrap. The cloud-init below isn't passed at create
time (FlokiNET's panel doesn't always honor it on every plan), so we
just paste-and-run as a shell script:

```bash
export VOIDMAIL_DOMAIN="<yourdomain>"
bash <<'BOOTSTRAP'
set -euo pipefail

# 1. Hostname.
hostnamectl set-hostname "mx.${VOIDMAIL_DOMAIN}"
echo "127.0.1.1 mx.${VOIDMAIL_DOMAIN}" >> /etc/hosts

# 2. Packages.
apt-get update -y
apt-get install -y ca-certificates curl git ufw fail2ban unattended-upgrades

# 3. Volatile journald — system logs evaporate on reboot.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/voidmail.conf <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=64M
ForwardToSyslog=no
EOF
systemctl restart systemd-journald

# 4. Disable bash history and last-log files (defense in depth).
echo 'unset HISTFILE' >> /etc/profile.d/no-history.sh
chmod +x /etc/profile.d/no-history.sh
ln -sf /dev/null /var/log/lastlog
ln -sf /dev/null /var/log/wtmp
ln -sf /dev/null /var/log/btmp

# 5. Docker (upstream).
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io \
                   docker-buildx-plugin docker-compose-plugin

# 6. Firewall: only what we serve. NO IMAP exposed (webmail only via Tor + clearnet).
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 25/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 587/tcp
ufw --force enable

# 7. Clone and configure.
git clone https://github.com/defthrets/qloakmail.git /opt/voidmail
cd /opt/voidmail
bash scripts/fetch-web-libs.sh

umask 077
cat > /opt/voidmail/.env <<EOF
VOIDMAIL_DOMAIN=${VOIDMAIL_DOMAIN}
VOIDMAIL_HOSTNAME=mx.${VOIDMAIL_DOMAIN}
VOIDMAIL_EXTRA_DOMAINS=
VOIDMAIL_PUBLIC_URL=https://${VOIDMAIL_DOMAIN}
POSTGRES_USER=voidmail
POSTGRES_PASSWORD=$(openssl rand -hex 24)
POSTGRES_DB=voidmail
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
REDIS_HOST=redis
REDIS_PORT=6379
API_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
API_BIND=0.0.0.0:8000
INVITE_CODES=$(openssl rand -hex 8)
CAPTCHA_PROVIDER=none
CAPTCHA_SECRET=
DOVECOT_LMTP_HOST=dovecot
DOVECOT_LMTP_PORT=24
ENCRYPT_PIPE_BIND=0.0.0.0:10025
INTERNAL_API_URL=http://api:8000
INTERNAL_API_TOKEN=$(openssl rand -hex 32)
RSPAMD_PASSWORD=$(openssl rand -hex 16)
DKIM_SELECTOR=mail
LETSENCRYPT_EMAIL=admin@${VOIDMAIL_DOMAIN}
LETSENCRYPT_STAGING=0
EOF
chmod 600 /opt/voidmail/.env

echo "================================================================"
echo "INVITE CODE (only way to sign up — save it):"
grep ^INVITE_CODES= /opt/voidmail/.env
echo "================================================================"

# 8. Build and start.
docker compose up -d --build
docker compose ps

# 9. Print the .onion when it's ready (tor takes ~30-60s on first run).
echo "Waiting for Tor hidden service to publish..."
for i in $(seq 1 30); do
    if docker compose exec -T tor cat /var/lib/tor/voidmail/hostname 2>/dev/null; then break; fi
    sleep 4
done
BOOTSTRAP
```

Save the printed invite code and the `.onion` address. The `.env`
file on the VPS is the only authoritative copy of your secrets —
back it up offline (`scp`) before it touches anything else.

---

## Step 6 — DNS records (in Njalla's panel)

Add these against your domain. Replace `<v4>` / `<v6>` with the FlokiNET
IPs and `<dkim>` with the public-key blob from
`docker compose exec postfix cat /etc/opendkim/keys/<domain>/mail.txt`.

| Type | Name | Value |
|---|---|---|
| A | `@` | `<v4>` |
| AAAA | `@` | `<v6>` |
| A | `mx` | `<v4>` |
| AAAA | `mx` | `<v6>` |
| MX | `@` | `10 mx.<domain>` |
| TXT | `@` | `v=spf1 mx -all` |
| TXT | `mail._domainkey` | `v=DKIM1; h=sha256; k=rsa; p=<dkim>` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>; adkim=s; aspf=s` |

DNS propagates within minutes through Njalla.

---

## Step 7 — Issue the Let's Encrypt cert (clearnet)

```bash
cd /opt/voidmail
docker compose stop nginx
docker run --rm -p 80:80 \
    -v voidmail_certs:/etc/letsencrypt \
    certbot/certbot certonly --standalone \
    -d <yourdomain> \
    --email admin@<yourdomain> --agree-tos --non-interactive
docker compose up -d nginx
```

Then automate renewal with a weekly cron entry:

```bash
echo '0 4 * * 1 cd /opt/voidmail && docker compose stop nginx && docker run --rm -p 80:80 -v voidmail_certs:/etc/letsencrypt certbot/certbot renew --standalone --quiet && docker compose up -d nginx' \
    | crontab -
```

> **Cert transparency note:** issuing a cert publishes the SAN in the
> public CT log. That ties your clearnet domain to your existence, but
> not to your IP (anyone can see the domain, not who runs it). The
> .onion side has no equivalent leak.

---

## Step 8 — Test the round-trip

* Browser → `https://<yourdomain>/` → webmail loads.
* Tor Browser → `http://<your-onion>/` → same SPA loads.
* Sign up using the invite code printed in Step 5. Save the recovery code.
* From a Gmail account, send to `you@<yourdomain>`.
* Watch:
  ```bash
  docker compose logs -f postfix encrypt-pipe
  ```
* Refresh inbox → message decrypts client-side.

Send a test to <https://www.mail-tester.com> for a deliverability score
(aim for 8+/10 on a fresh domain).

---

## Step 9 — Operational hygiene

After deploy, do these once:

1. **Back up `.env`** offline (it has all your secrets).
2. **Back up the `tor-keys` volume** if you want a stable .onion forever:
   ```bash
   docker run --rm -v voidmail_tor-keys:/data -v $(pwd):/backup alpine tar czf /backup/tor-keys.tar.gz -C /data .
   ```
3. **Disable SSH password auth**:
   ```bash
   sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
   systemctl restart sshd
   ```
4. **Enable unattended security updates** (already installed by the
   bootstrap):
   ```bash
   dpkg-reconfigure --priority=low unattended-upgrades
   ```

Routinely:

* `docker compose pull && docker compose up -d --build` — pulls latest
  base images and rebuilds.
* Tail logs only when investigating; the docker driver is capped at
  30 MB per service so they roll naturally.
* Rotate the `INVITE_CODES` value in `.env` whenever you want to close
  signups.

---

## What this deployment does NOT log

| Source | What's stored |
|---|---|
| API access log | nothing — uvicorn `--no-access-log` |
| API error log | exception traces (no IPs, no email-content); rolls at 30 MB |
| Sessions table | `account_id`, `token_hash`, `created_at`, `expires_at` only |
| Redis sessions | opaque token → account_id, TTL'd |
| Redis rate limits | HMAC(IP) → counter, 1-hour TTL max |
| postfix/mail.log | inbound SMTP envelopes (mandatory for routing); rolls at 30 MB |
| systemd journal | volatile, RAM-only, 64 MB cap, lost on reboot |
| bash history | disabled |
| wtmp/lastlog/btmp | symlinked to /dev/null |
| Cloudflare/registrar | nothing — Njalla holds the domain |
| Payment trail | nothing — Monero |

The only IP a QloakMail user reveals is to the Tor entry guard (if they
use the .onion) or to nginx (if they use clearnet). Postfix sees the
*sender's* server IP for inbound mail — that's the SMTP envelope, which
no MTA can hide.
