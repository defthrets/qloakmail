# QloakMail security hardening — operator runbook

Companion to the in-code changes. Contains DNS records, third-party
sign-ups, and shell snippets that must be applied at the registrar /
VPS / certificate level — they can't live in the codebase.

Walk through each section in order. Items are independent — partial
adoption is fine.

---

## 1. DNS records (1984 Hosting registrar UI)

### MTA-STS

```
mta-sts.qloak.me.         IN A     82.221.101.24
mta-sts.qloak.me.         IN AAAA  <ipv6 if any>
_mta-sts.qloak.me.        IN TXT   "v=STSv1; id=2026051001"
_smtp._tls.qloak.me.      IN TXT   "v=TLSRPTv1; rua=mailto:tls-reports@qloak.me"
```

The `id=` value is a freeform version string. Bump it (e.g. to
`id=2026051002`) any time the policy file at
`https://mta-sts.qloak.me/.well-known/mta-sts.txt` changes.

### CAA — restrict who can issue certs for the domain

```
qloak.me.   IN CAA  0 issue     "letsencrypt.org"
qloak.me.   IN CAA  0 issuewild ";"
qloak.me.   IN CAA  0 iodef     "mailto:abuse@qloak.me"
```

Any CA other than Let's Encrypt will refuse to issue a cert for
`qloak.me`. Wildcards are forbidden. Misissuance attempts are
emailed to `abuse@`.

### DNSSEC

1984 Hosting has a "Enable DNSSEC" toggle in their domain panel. Turn
it on. They generate the DS records and publish them upstream.

Verify after a few hours:

```
dig +dnssec qloak.me SOA
```

`ad` flag in the response means DNSSEC is validating end-to-end.

### DANE TLSA — pin the SMTP cert

```
_25._tcp.mx.qloak.me.   IN TLSA  3 1 1 <sha256 of cert pubkey>
```

`3 1 1` means: `DANE-EE` (end-entity), `SPKI` (subject public key
info), `SHA-256`. Generate the hash with:

```bash
openssl x509 -in /etc/letsencrypt/live/qloak.me/cert.pem \
    -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256 -binary |
  xxd -p -c 256
```

Keep two TLSA records (current + next) during cert rollover so
clients don't fail when the cert rotates.

DANE only works if DNSSEC is on (above). Without DNSSEC the TLSA
record is unauthenticated and ignored by spec-compliant verifiers.

---

## 2. HSTS preload

Once HSTS has been live for a week with `max-age=63072000`,
`includeSubDomains`, and `preload`, submit at:

  https://hstspreload.org

Once accepted, modern browsers ship knowing `qloak.me` is HTTPS-only.
Even a first-time visitor with no prior HSTS record will refuse HTTP.

Removal is slow (months) — only submit after you're sure every
qloak.me subdomain is HTTPS-ready.

---

## 3. Certificate Transparency monitoring

Sign up at one of:

  * https://crt.sh  (free, search-only)
  * https://sslmate.com/certspotter (free tier, alerts)
  * https://www.facebook.com/CertificateTransparency (free alerts)

Configure alerts for `qloak.me` and `*.qloak.me`. Any new cert issued
for the domain — including a misissuance by a rogue CA — will fire
within minutes of CT log inclusion.

---

## 4. fail2ban on the VPS

Defends SSH / submission / IMAPS against brute-forcers. Protections
apply at iptables level, before our app rate limits.

```bash
sudo apt-get install -y fail2ban

sudo tee /etc/fail2ban/jail.d/qloakmail.conf >/dev/null <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[postfix-sasl]
enabled = true
port    = smtp,submission,smtps

[dovecot]
enabled = true
port    = pop3,pop3s,imap,imaps,submission,465,sieve
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status
```

Logs in `/var/log/fail2ban.log`. To unban an IP:

```bash
sudo fail2ban-client set sshd unbanip <ip>
```

---

## 5. SSH lockdown

```bash
# /etc/ssh/sshd_config.d/qloakmail-hardening.conf
PasswordAuthentication no
PermitRootLogin no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers spitmux
LoginGraceTime 30
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

Reload: `sudo systemctl reload ssh`. Verify your key still works
**before** closing your existing session.

Optional further hardening: move SSH off port 22 to an unprivileged
port (cuts log noise from internet scanners by ~99%) and put it
behind WireGuard so the SSH port isn't world-reachable at all.

---

## 6. Container hardening (later, separate commit)

Outline only — implementation is bigger:

```yaml
# docker-compose.yml — per service
read_only: true
tmpfs:
  - /tmp
  - /run
cap_drop: [ALL]
cap_add: [NET_BIND_SERVICE]   # postfix only; api/dovecot drop more
security_opt:
  - no-new-privileges:true
  - seccomp:default            # docker default already strict
```

Plus an `internal: true` bridge network for `db` / `redis` so they
aren't reachable from the host or other networks.

---

## 7. Off-site encrypted backups

`restic` to a B2 / rsync.net bucket in a different jurisdiction.
Master passphrase generated locally, kept in offline cold storage:

```bash
sudo apt-get install -y restic
restic init -r b2:qloakmail-backups:/voidmail
restic backup -r b2:qloakmail-backups:/voidmail \
    /opt/voidmail/data \
    /etc/letsencrypt
```

Cron weekly. Test restores quarterly.

---

## 8. Warrant canary — weekly cron

`scripts/refresh-canary.sh` regenerates `web/.well-known/canary.txt`
with the latest Bitcoin block hash and an updated cleartext PGP
signature. Run weekly:

```cron
# /etc/cron.d/qloakmail-canary
0 9 * * 1 spitmux GPG_KEY_ID=<operator key> /opt/voidmail/scripts/refresh-canary.sh && cd /opt/voidmail && git -c user.email=ops@qloak.me -c user.name='canary' commit -am "canary: weekly refresh" && git push
```

If two consecutive Mondays pass without a refresh, users should
treat that as a signal.

---

## 9. CSP report-uri (optional)

To get visibility into CSP violations without leaking user data, add
a minimal report endpoint behind the same origin:

```
add_header Content-Security-Policy "...same as before...; report-uri /api/v1/csp-report" always;
```

API endpoint should accept POST, drop everything except the violation
type and a coarse timestamp bucket, and write nothing if the report
is empty. Skip if you don't want to operate it — defaults are fine.
