#!/bin/sh
# Render nginx config from envvars at container start, and ensure a TLS
# cert exists at the Let's Encrypt path so the HTTPS server block loads
# (a real cert from certbot will overwrite the self-signed one in prod).
set -eu

LE_DIR="/etc/letsencrypt/live/${VOIDMAIL_DOMAIN}"
if [ ! -f "${LE_DIR}/fullchain.pem" ] || [ ! -f "${LE_DIR}/privkey.pem" ]; then
    echo "[nginx] generating self-signed cert for ${VOIDMAIL_DOMAIN} at ${LE_DIR}"
    mkdir -p "${LE_DIR}"
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "${LE_DIR}/privkey.pem" \
        -out    "${LE_DIR}/fullchain.pem" \
        -subj   "/CN=${VOIDMAIL_DOMAIN}" >/dev/null 2>&1
    chmod 600 "${LE_DIR}/privkey.pem"
fi

# Webroot for the ACME challenge (used in prod by certbot).
mkdir -p /var/www/certbot

# Re-render every container start so envvar changes take effect. Keep the
# template in place — deleting it on first run made the script crash on
# every subsequent container restart with "voidmail.conf.template: no
# such file" (the rendered .conf alone isn't a substitute since we'd
# never re-render for new env values).
envsubst '${VOIDMAIL_DOMAIN}' < /etc/nginx/conf.d/voidmail.conf.template \
    > /etc/nginx/conf.d/voidmail.conf
rm -f /etc/nginx/conf.d/default.conf || true
