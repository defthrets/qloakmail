#!/usr/bin/env bash
# Diagnose whether outbound SMTP (port 25) is actually allowed off this
# host. FlokiNET blocks ports 25 / 465 / 587 egress by default on new
# VPSes -- this script tells you, in 20 seconds, whether you're hitting
# that block before you bother filing the unblock ticket.
#
# Runs from inside the postfix container so we test from the SAME
# network namespace that postfix would use. Run as:
#
#   sudo ./scripts/check-outbound-smtp.sh
#
# A "blocked" result means FlokiNET (or any upstream firewall) is
# dropping the SYN -- the connect just times out. An "open with banner"
# result means traffic flows and the remote MTA answered. "Refused"
# means the upstream MTA actively rejected the connection (rare).

set -u

# Pick a few well-known, geographically diverse MX hosts that are
# unlikely to all be down at once. Each line is "label host port".
TARGETS=(
    "gmail   gmail-smtp-in.l.google.com  25"
    "outlook outlook-com.olc.protection.outlook.com  25"
    "proton  mail.protonmail.ch  25"
    "submission587 smtp.gmail.com  587"
    "submission465 smtp.gmail.com  465"
)

# Find the postfix container -- assume the standard compose name.
CTR=$(docker ps --filter "name=postfix" --format '{{.Names}}' | head -n1)
if [ -z "$CTR" ]; then
    echo "[!] No running 'postfix' container found." >&2
    echo "    Start the stack with: docker compose up -d" >&2
    exit 2
fi
echo "[*] Testing outbound from container: $CTR"
echo

# Ensure netcat is available inside the container. Postfix images
# usually have it via ncat (nmap-ncat) or netcat-openbsd; if neither
# is present, fall back to bash's /dev/tcp.
HAS_NC=$(docker exec "$CTR" sh -c 'command -v nc || command -v ncat' 2>/dev/null | head -n1)
TIMEOUT_BIN=$(docker exec "$CTR" sh -c 'command -v timeout' 2>/dev/null | head -n1)

probe() {
    local label="$1" host="$2" port="$3"
    printf "  %-15s %s:%s  " "[$label]" "$host" "$port"

    if [ -n "$HAS_NC" ] && [ -n "$TIMEOUT_BIN" ]; then
        # nc -z fails fast on a closed/firewalled port; with -w we cap
        # the wait. -v prints "open" / "refused" on stderr.
        if docker exec "$CTR" sh -c "$TIMEOUT_BIN 8 $HAS_NC -zvw 5 $host $port" >/dev/null 2>&1; then
            # Connected -- now read the SMTP banner to prove it's
            # really an MTA on the other side (not a captive portal).
            banner=$(docker exec "$CTR" sh -c \
                "$TIMEOUT_BIN 8 sh -c 'exec 3<>/dev/tcp/$host/$port; echo QUIT >&3; head -n1 <&3'" 2>/dev/null \
                | tr -d '\r\n' | cut -c1-72)
            if [ -n "$banner" ]; then
                echo "OPEN -- banner: \"$banner\""
            else
                echo "OPEN (no banner read, but TCP connect succeeded)"
            fi
        else
            echo "BLOCKED / TIMEOUT  <-- firewall is dropping SYN"
        fi
    else
        # Fallback: bash /dev/tcp. Works in most modern shells.
        if docker exec "$CTR" bash -c "exec 3<>/dev/tcp/$host/$port && echo QUIT >&3 && read -t 5 -r line <&3 && echo \"OPEN -- banner: \\\"\$line\\\"\"" 2>/dev/null; then
            : # output handled inline
        else
            echo "BLOCKED / TIMEOUT  <-- firewall is dropping SYN"
        fi
    fi
}

for line in "${TARGETS[@]}"; do
    # shellcheck disable=SC2086
    set -- $line
    probe "$1" "$2" "$3"
done

echo
echo "Reading: any line that prints OPEN means egress to that port works."
echo "All BLOCKED on port 25 means the upstream firewall is dropping it."
echo "Mixed results (e.g. 587 open, 25 blocked) is also informative --"
echo "outbound SMTP delivery to other servers fundamentally needs :25."
