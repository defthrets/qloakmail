#!/usr/bin/env bash
# Generate a DKIM keypair for a domain INSIDE the rspamd container.
#
#   ./scripts/generate-dkim.sh qloak.me [mail]
#
# Writes the private key to /var/lib/rspamd/dkim/<domain>/<selector>.key
# in the rspamd-data volume (so it survives container restarts).
# Prints the DNS TXT record to publish at <selector>._domainkey.<domain>.
#
# rspamd's signing module is configured in rspamd/local.d/dkim_signing.conf
# to look up keys at that exact path, so once both the key file and the
# DNS TXT record are in place, outbound mail starts being signed
# automatically — no rspamd restart needed (rspamd notices new keys).
set -euo pipefail

DOMAIN="${1:-}"
SELECTOR="${2:-mail}"

if [ -z "$DOMAIN" ]; then
    echo "usage: $0 <domain> [selector]" >&2
    exit 2
fi

# All work runs inside the rspamd container so the keys land on the
# correct volume with the right owner (_rspamd) and the rspamadm
# binary is available without local install.
COMPOSE="docker compose"
SVC="rspamd"
DIR="/var/lib/rspamd/dkim/${DOMAIN}"

echo "==> generating ${SELECTOR}._domainkey.${DOMAIN} inside ${SVC} container"
$COMPOSE exec -T "$SVC" sh -eu -c "
    mkdir -p '${DIR}'
    chown _rspamd:_rspamd '${DIR}'
    cd '${DIR}'
    if [ -f '${SELECTOR}.key' ]; then
        echo 'key already exists at ${DIR}/${SELECTOR}.key — refusing to overwrite' >&2
        exit 3
    fi
    rspamadm dkim_keygen -s '${SELECTOR}' -d '${DOMAIN}' -k '${SELECTOR}.key' -b 2048 > '${SELECTOR}.pub'
    chown _rspamd:_rspamd '${SELECTOR}.key' '${SELECTOR}.pub'
    chmod 600 '${SELECTOR}.key'
    chmod 644 '${SELECTOR}.pub'
    echo
    echo '==> private key written: ${DIR}/${SELECTOR}.key'
    echo '==> publish this TXT record at ${SELECTOR}._domainkey.${DOMAIN}:'
    echo
    cat '${SELECTOR}.pub'
"
