#!/usr/bin/env bash
set -euo pipefail

# Render templated configs ----------------------------------------------------

: "${VOIDMAIL_DOMAIN:?must be set}"
: "${VOIDMAIL_HOSTNAME:?must be set}"

envsubst < /etc/postfix/main.cf.tmpl   > /etc/postfix/main.cf
cp       /etc/postfix/master.cf.tmpl     /etc/postfix/master.cf

# Build a PCRE regex matching every served domain.
DOMAINS="$VOIDMAIL_DOMAIN"
if [ -n "${VOIDMAIL_EXTRA_DOMAINS:-}" ]; then
    DOMAINS="$DOMAINS,$VOIDMAIL_EXTRA_DOMAINS"
fi
PCRE="/^("
first=1
IFS=','; for d in $DOMAINS; do
    d="$(echo "$d" | xargs)"
    [ -z "$d" ] && continue
    [ $first -eq 0 ] && PCRE="$PCRE|"
    PCRE="$PCRE$(echo "$d" | sed 's/\./\\./g')"
    first=0
done
PCRE="$PCRE)$/  ANY"
echo "$PCRE" > /etc/postfix/virtual-domains
echo "$PCRE" > /etc/postfix/virtual-accept

# OpenDKIM ---------------------------------------------------------------------

DKIM_SELECTOR="${DKIM_SELECTOR:-mail}"
DKIM_DIR="/etc/opendkim/keys/${VOIDMAIL_DOMAIN}"

mkdir -p /etc/opendkim /var/run/opendkim "$DKIM_DIR"
envsubst < /etc/opendkim/opendkim.conf.tmpl > /etc/opendkim/opendkim.conf

# KeyTable / SigningTable
cat > /etc/opendkim/KeyTable <<EOF
${DKIM_SELECTOR}._domainkey.${VOIDMAIL_DOMAIN} ${VOIDMAIL_DOMAIN}:${DKIM_SELECTOR}:${DKIM_DIR}/${DKIM_SELECTOR}.private
EOF
cat > /etc/opendkim/SigningTable <<EOF
*@${VOIDMAIL_DOMAIN} ${DKIM_SELECTOR}._domainkey.${VOIDMAIL_DOMAIN}
EOF

# Generate a DKIM key if there isn't one (dev convenience).
if [ ! -f "${DKIM_DIR}/${DKIM_SELECTOR}.private" ]; then
    echo "[entrypoint] generating DKIM key for ${VOIDMAIL_DOMAIN}" >&2
    opendkim-genkey -b 2048 -s "${DKIM_SELECTOR}" -d "${VOIDMAIL_DOMAIN}" -D "$DKIM_DIR"
    chown -R opendkim:opendkim "$DKIM_DIR"
    chmod 600 "${DKIM_DIR}/${DKIM_SELECTOR}.private"
    echo "[entrypoint] DKIM public record (publish in DNS as TXT @ ${DKIM_SELECTOR}._domainkey.${VOIDMAIL_DOMAIN}):" >&2
    cat "${DKIM_DIR}/${DKIM_SELECTOR}.txt" >&2
fi

# Run OpenDKIM in background, then exec Postfix in the foreground.
opendkim -f -x /etc/opendkim/opendkim.conf -p inet:8891@0.0.0.0 &
OPENDKIM_PID=$!

# Postfix needs writable spool — first-time fixup.
postfix set-permissions || true
postfix check

# Foreground postfix: tail master log to stdout so docker logs picks it up.
postfix start-fg &
POSTFIX_PID=$!

trap 'kill $POSTFIX_PID $OPENDKIM_PID 2>/dev/null || true' SIGTERM SIGINT
wait -n
