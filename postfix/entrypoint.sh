#!/usr/bin/env bash
set -euo pipefail

# Render templated configs ----------------------------------------------------

: "${VOIDMAIL_DOMAIN:?must be set}"
: "${VOIDMAIL_HOSTNAME:?must be set}"

# Limit envsubst to OUR variables — postfix configs use $foo for their
# own runtime variables ($mydomain, $smtpd_milters etc.) which we must
# leave alone. Without the allowlist envsubst replaces them with "".
envsubst '${VOIDMAIL_DOMAIN} ${VOIDMAIL_HOSTNAME}' \
    < /etc/postfix/main.cf.tmpl > /etc/postfix/main.cf
cp /etc/postfix/master.cf.tmpl /etc/postfix/master.cf

# Build domain-alternation regex body: e.g. "voidmail\.local|other\.dev"
DOMAINS="$VOIDMAIL_DOMAIN"
if [ -n "${VOIDMAIL_EXTRA_DOMAINS:-}" ]; then
    DOMAINS="$DOMAINS,$VOIDMAIL_EXTRA_DOMAINS"
fi
DOMAIN_ALT=""
IFS=','
for d in $DOMAINS; do
    d="$(echo "$d" | xargs)"
    [ -z "$d" ] && continue
    [ -n "$DOMAIN_ALT" ] && DOMAIN_ALT="${DOMAIN_ALT}|"
    DOMAIN_ALT="${DOMAIN_ALT}$(echo "$d" | sed 's/\./\\./g')"
done
unset IFS
# virtual_mailbox_domains is keyed on bare domain.
echo "/^(${DOMAIN_ALT})\$/  ANY" > /etc/postfix/virtual-domains
# virtual_mailbox_maps is keyed on full address (local@domain).
echo "/^[^@]+@(${DOMAIN_ALT})\$/  ANY" > /etc/postfix/virtual-accept

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

# Configure rsyslog: forward mail.* to stdout so `docker logs` sees it.
cat > /etc/rsyslog.d/01-mail-to-stdout.conf <<'EOF'
# Containerised: write all mail facility messages to /dev/stdout.
$ModLoad imuxsock
mail.*    -/dev/stdout
EOF
# Strip distro defaults that may try to write to non-existent paths.
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf || true

rsyslogd
echo "[entrypoint] rsyslogd started" >&2

# Postfix needs writable spool — first-time fixup.
postfix set-permissions || true
# `postfix check` is diagnostic only; warnings here shouldn't block startup
# (e.g. missing TLS chain files when running without a cert).
postfix check || true

echo "[entrypoint] running opendkim..." >&2
# Run opendkim in the foreground (-f) and background it explicitly with `&`
# so the entrypoint can keep running. Without -f, opendkim daemonises but
# in some configurations exits non-zero (e.g. pidfile race) which trips
# `set -e` and kills the entrypoint silently.
opendkim -f -x /etc/opendkim/opendkim.conf -p inet:8891@0.0.0.0 >&2 &
OPENDKIM_PID=$!
echo "[entrypoint] opendkim pid $OPENDKIM_PID" >&2

# Start postfix in daemon mode. The master process re-parents under
# init (PID 1 of the container == this script) and runs in the
# background; `postfix start` returns immediately.
echo "[entrypoint] starting postfix..." >&2
postfix start
echo "[entrypoint] postfix start ok" >&2

trap 'echo "[entrypoint] stopping" >&2; postfix stop 2>/dev/null || true; kill $OPENDKIM_PID 2>/dev/null || true; exit 0' SIGTERM SIGINT

# Hold the container open and stream mail log to docker stdout.
exec tail -F /var/log/mail.log
