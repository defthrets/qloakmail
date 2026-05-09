#!/usr/bin/env bash
set -euo pipefail

# Hash the operator's password (only used for the rspamd web UI).
if [ -n "${RSPAMD_PASSWORD:-}" ]; then
    HASH=$(rspamadm pw -p "$RSPAMD_PASSWORD" -q)
    cat > /etc/rspamd/local.d/worker-controller.inc <<EOF
password = "$HASH";
secure_ip = "127.0.0.1, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
EOF
fi

exec rspamd -f -u _rspamd -g _rspamd
