#!/usr/bin/env bash
# Refresh the QloakMail warrant canary.
#
# Anchors the statement to the latest Bitcoin block hash (so it can't
# have been pre-signed in the past), fills in the date, and signs with
# the operator GPG key. Run weekly via cron — if it stops running and
# the canary is more than 14 days stale, users should treat that as
# a signal that something has changed.
#
# Usage:
#   GPG_KEY_ID=ABCD1234... ./scripts/refresh-canary.sh
#
# Requirements: curl, jq, gpg, awk, sed.

set -euo pipefail

CANARY_PATH="${CANARY_PATH:-web/.well-known/canary.txt}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

if [ -z "$GPG_KEY_ID" ]; then
    echo "GPG_KEY_ID env var required (long-form key id of the operator key)" >&2
    exit 1
fi

# Latest Bitcoin block height + hash via blockstream.info (Tor-friendly,
# also reachable as http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion).
TIP_HEIGHT="$(curl -fsS https://blockstream.info/api/blocks/tip/height)"
TIP_HASH="$(curl -fsS "https://blockstream.info/api/block-height/${TIP_HEIGHT}")"
TODAY="$(date -u +"%Y-%m-%d")"

# Build the unsigned body.
BODY=$(cat <<EOF
QloakMail Warrant Canary
========================

As of the date below, QloakMail has:

  * NEVER received a National Security Letter or other secret subpoena.
  * NEVER been compelled to install backdoors or modify our software
    in a way that weakens user security.
  * NEVER handed over user plaintext, private keys, or any data we
    are unable to decrypt — because by design we cannot.
  * NEVER received a gag order preventing us from updating this canary.

If this canary is not refreshed within 14 days of the timestamp below,
or if it is removed entirely, treat that as a signal that something
may have changed — and act accordingly.

Refreshed:    ${TODAY}
Bitcoin block height (anchor): ${TIP_HEIGHT}
Bitcoin block hash   (anchor): ${TIP_HASH}
EOF
)

# Detached cleartext-sign the body and write the canary file.
SIGNED=$(printf '%s\n' "$BODY" | gpg --clearsign --local-user "$GPG_KEY_ID" --armor)

cat > "$CANARY_PATH" <<EOF
${SIGNED}
EOF

echo "Canary refreshed at ${CANARY_PATH} (block ${TIP_HEIGHT})."
