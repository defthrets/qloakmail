#!/usr/bin/env bash
set -euo pipefail

# Substitute postgres creds into the SQL backend config.
sed -i \
    -e "s|__POSTGRES_DB__|${POSTGRES_DB}|g" \
    -e "s|__POSTGRES_USER__|${POSTGRES_USER}|g" \
    -e "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" \
    /etc/dovecot/conf.d/dovecot-sql.conf.ext

# Self-signed cert for IMAPS in dev. Production uses certs from the
# `certs` volume populated by certbot — replace these on first start.
if [ ! -f /etc/dovecot/ssl/cert.pem ]; then
    mkdir -p /etc/dovecot/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/dovecot/ssl/key.pem \
        -out    /etc/dovecot/ssl/cert.pem \
        -subj   "/CN=${VOIDMAIL_HOSTNAME:-mx.voidmail.local}"
    chmod 600 /etc/dovecot/ssl/key.pem
fi

exec dovecot -F
