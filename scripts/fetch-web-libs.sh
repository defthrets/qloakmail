#!/usr/bin/env bash
# Download the vendored web libraries the SPA needs.
set -euo pipefail

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)/web/lib"
mkdir -p "$LIB_DIR"

OPENPGP_VER="${OPENPGP_VER:-5.11.2}"
HASHWASM_VER="${HASHWASM_VER:-4.11.0}"

echo "==> openpgp.js ${OPENPGP_VER}"
curl -fsSL "https://cdn.jsdelivr.net/npm/openpgp@${OPENPGP_VER}/dist/openpgp.min.js" \
    -o "$LIB_DIR/openpgp.min.js"

echo "==> hash-wasm ${HASHWASM_VER}"
curl -fsSL "https://cdn.jsdelivr.net/npm/hash-wasm@${HASHWASM_VER}/dist/index.umd.min.js" \
    -o "$LIB_DIR/hash-wasm.umd.min.js"

echo
echo "Vendored libraries written to $LIB_DIR:"
ls -la "$LIB_DIR"
