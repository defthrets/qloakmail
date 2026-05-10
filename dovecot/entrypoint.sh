#!/usr/bin/env bash
set -euo pipefail

# Substitute postgres creds into the SQL backend config.
sed -i \
    -e "s|__POSTGRES_DB__|${POSTGRES_DB}|g" \
    -e "s|__POSTGRES_USER__|${POSTGRES_USER}|g" \
    -e "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" \
    /etc/dovecot/conf.d/dovecot-sql.conf.ext

# TLS cert wiring.
#   * Production (certs volume mounted at /etc/letsencrypt): point
#     dovecot.conf at the LE fullchain + privkey directly.
#   * Dev (no LE): generate a self-signed cert under /etc/dovecot/ssl
#     so IMAPS at least starts.
LE_CERT="/etc/letsencrypt/live/${VOIDMAIL_DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/${VOIDMAIL_DOMAIN}/privkey.pem"
if [ -f "$LE_CERT" ] && [ -f "$LE_KEY" ]; then
    sed -i \
        -e "s|^ssl_cert = .*|ssl_cert = <${LE_CERT}|" \
        -e "s|^ssl_key  = .*|ssl_key  = <${LE_KEY}|" \
        /etc/dovecot/dovecot.conf
elif [ ! -f /etc/dovecot/ssl/cert.pem ]; then
    mkdir -p /etc/dovecot/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/dovecot/ssl/key.pem \
        -out    /etc/dovecot/ssl/cert.pem \
        -subj   "/CN=${VOIDMAIL_HOSTNAME:-mx.voidmail.local}"
    chmod 600 /etc/dovecot/ssl/key.pem
fi

exec dovecot -F
