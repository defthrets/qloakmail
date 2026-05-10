#!/usr/bin/env bash
# Recompute SRI sha384 hashes for the bundled crypto libs.
# Print pasteable integrity= attributes for index.html.
#
# Run after upgrading openpgp.js or hash-wasm. Update both the file
# in web/lib AND the corresponding integrity= attribute in
# web/index.html in the same commit, otherwise the browser refuses to
# run the script and the SPA breaks.

set -euo pipefail
cd "$(dirname "$0")/../web/lib"

for f in openpgp.min.js hash-wasm.umd.min.js; do
    if [ ! -f "$f" ]; then
        echo "missing: $f" >&2
        exit 1
    fi
    h=$(openssl dgst -sha384 -binary "$f" | openssl base64 -A)
    printf '  %s\n    integrity="sha384-%s"\n' "$f" "$h"
done
