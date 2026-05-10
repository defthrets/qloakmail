#!/usr/bin/env bash
# Recompute SRI sha384 hashes for the SPA bundle.
# Prints pasteable integrity= attributes for web/index.html.
#
# Run any time app.js or one of the bundled libs changes. Update both
# the file AND the corresponding integrity= attribute in index.html in
# the same commit — otherwise the browser refuses to run the script and
# the SPA breaks.

set -euo pipefail
WEB="$(cd "$(dirname "$0")/../web" && pwd)"

hash_of() { openssl dgst -sha384 -binary "$1" | openssl base64 -A; }

# Bundled vendor libs.
for f in lib/openpgp.min.js lib/hash-wasm.umd.min.js; do
    p="$WEB/$f"
    [ -f "$p" ] || { echo "missing: $f" >&2; exit 1; }
    printf '  %s\n    integrity="sha384-%s"\n' "$f" "$(hash_of "$p")"
done

# App bundle.
p="$WEB/app.js"
[ -f "$p" ] || { echo "missing: app.js" >&2; exit 1; }
printf '  %s\n    integrity="sha384-%s"\n' "app.js" "$(hash_of "$p")"
