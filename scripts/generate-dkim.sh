#!/usr/bin/env bash
# Generate a DKIM keypair for a domain.
#
#   ./scripts/generate-dkim.sh voidmail.tld mail
#
# Writes private key to postfix/opendkim/keys/<domain>/<selector>.private
# and prints the DNS TXT record you need to publish.
set -euo pipefail

DOMAIN="${1:-}"
SELECTOR="${2:-mail}"

if [ -z "$DOMAIN" ]; then
    echo "usage: $0 <domain> [selector]"
    exit 2
fi

OUT="$(dirname "$0")/../postfix/opendkim/keys/${DOMAIN}"
mkdir -p "$OUT"

if ! command -v opendkim-genkey >/dev/null; then
    echo "opendkim-genkey not found. Install opendkim-tools (apt) or run inside the postfix container:"
    echo "  docker compose exec postfix opendkim-genkey -b 2048 -s ${SELECTOR} -d ${DOMAIN} -D /etc/opendkim/keys/${DOMAIN}"
    exit 1
fi

opendkim-genkey -b 2048 -s "$SELECTOR" -d "$DOMAIN" -D "$OUT"
chmod 600 "${OUT}/${SELECTOR}.private"

echo
echo "==> DKIM private key written to ${OUT}/${SELECTOR}.private"
echo "==> Publish this TXT record at ${SELECTOR}._domainkey.${DOMAIN}:"
echo
cat "${OUT}/${SELECTOR}.txt"
