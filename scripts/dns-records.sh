#!/usr/bin/env bash
# Print the DNS records you need for a VoidMail domain.
#
#   ./scripts/dns-records.sh voidmail.tld [public-ipv4] [public-ipv6]
set -euo pipefail

DOMAIN="${1:-}"
IPV4="${2:-<your-ipv4>}"
IPV6="${3:-<your-ipv6>}"
SELECTOR="${DKIM_SELECTOR:-mail}"

if [ -z "$DOMAIN" ]; then
    echo "usage: $0 <domain> [ipv4] [ipv6]"
    exit 2
fi

DKIM_FILE="$(dirname "$0")/../postfix/opendkim/keys/${DOMAIN}/${SELECTOR}.txt"
if [ -f "$DKIM_FILE" ]; then
    DKIM_VALUE="$(grep -oP '"v=DKIM1[^"]+"' "$DKIM_FILE" | tr -d '\n"' | sed 's/  */ /g')"
else
    DKIM_VALUE="(run scripts/generate-dkim.sh first)"
fi

cat <<EOF
=== VoidMail DNS records for ${DOMAIN} ===

A      ${DOMAIN}.                       ${IPV4}
AAAA   ${DOMAIN}.                       ${IPV6}
A      mx.${DOMAIN}.                    ${IPV4}
AAAA   mx.${DOMAIN}.                    ${IPV6}

MX     ${DOMAIN}.                       10 mx.${DOMAIN}.

# SPF — only the MX server may send for this domain.
TXT    ${DOMAIN}.                       "v=spf1 mx -all"

# DKIM — published from generate-dkim.sh output.
TXT    ${SELECTOR}._domainkey.${DOMAIN}.   ${DKIM_VALUE}

# DMARC — strict alignment, quarantine on failure, aggregate reports.
TXT    _dmarc.${DOMAIN}.                "v=DMARC1; p=quarantine; rua=mailto:dmarc@${DOMAIN}; adkim=s; aspf=s; fo=1"

# MTA-STS / TLS-RPT (recommended).
TXT    _mta-sts.${DOMAIN}.              "v=STSv1; id=$(date +%Y%m%d01)"
TXT    _smtp._tls.${DOMAIN}.            "v=TLSRPTv1; rua=mailto:tls-reports@${DOMAIN}"

# Reverse DNS (set with your VPS provider's control panel — FlokiNET supports this on request)
PTR    <reverse-of-${IPV4}>.in-addr.arpa.   mx.${DOMAIN}.
EOF
