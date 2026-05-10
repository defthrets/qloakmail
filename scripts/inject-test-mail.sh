#!/usr/bin/env bash
# Pipe a test message into Postfix so we can exercise the encryption pipe
# without the public internet.
#
#   ./scripts/inject-test-mail.sh alice@voidmail.local 'Hello' 'Test body'
#
# Postfix is reachable on localhost:25 (mapped by docker-compose).
set -euo pipefail

TO="${1:-}"
SUBJECT="${2:-Hello from inject-test-mail.sh}"
BODY="${3:-If you can read this in your inbox, encryption + delivery worked.}"
FROM="${FROM:-tester@example.com}"

if [ -z "$TO" ]; then
    echo "usage: $0 <to> [subject] [body]"
    exit 2
fi

MSG=$(cat <<EOF
From: ${FROM}
To: ${TO}
Subject: ${SUBJECT}
Date: $(date -R 2>/dev/null || date)
Message-ID: <$(date +%s)@inject.voidmail>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

${BODY}
EOF
)

if command -v swaks >/dev/null; then
    swaks --to "$TO" --from "$FROM" --server 127.0.0.1:25 \
          --header "Subject: ${SUBJECT}" --body "$BODY"
else
    echo "$MSG" | curl --url "smtp://127.0.0.1:25" \
        --mail-from "$FROM" --mail-rcpt "$TO" \
        --upload-file - -v
fi
