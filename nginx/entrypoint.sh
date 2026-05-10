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

# Onion-Location header snippet. If Tor has bootstrapped and exposed
# the hidden-service hostname (read-only volume from the tor service),
# emit an Onion-Location header on the clearnet HTTPS response so
# Tor Browser auto-offers the .onion to users who visit via clearnet.
# If the hostname file isn't present yet (first deploy, Tor still
# bootstrapping), the snippet is empty and nginx serves clearnet only.
# Restart nginx once after Tor finishes its first bootstrap to pick
# up the header; afterwards keys persist in the tor-keys volume so
# this is a one-time step.
ONION_SNIPPET=/etc/nginx/conf.d/onion-location.inc
ONION_FILE=/var/lib/tor/voidmail/hostname
if [ -r "$ONION_FILE" ]; then
    ONION_HOST=$(tr -d '[:space:]' < "$ONION_FILE")
    if [ -n "$ONION_HOST" ]; then
        echo "add_header Onion-Location \"http://${ONION_HOST}\$request_uri\" always;" > "$ONION_SNIPPET"
        echo "[nginx] Onion-Location: http://${ONION_HOST}"
    else
        : > "$ONION_SNIPPET"
    fi
else
    : > "$ONION_SNIPPET"
    echo "[nginx] no onion hostname yet -- Onion-Location header disabled"
fi

# Re-render every container start so envvar changes take effect. Keep the
# template in place — deleting it on first run made the script crash on
# every subsequent container restart with "voidmail.conf.template: no
# such file" (the rendered .conf alone isn't a substitute since we'd
# never re-render for new env values).
envsubst '${VOIDMAIL_DOMAIN}' < /etc/nginx/conf.d/voidmail.conf.template \
    > /etc/nginx/conf.d/voidmail.conf
rm -f /etc/nginx/conf.d/default.conf || true
