# Vendored client libraries

VoidMail's CSP forbids loading scripts from external origins, so the SPA
loads its crypto libraries from this directory. They are NOT committed to
the repo — fetch them once with `scripts/fetch-web-libs.sh`.

Required files:

| File                          | Source                                                                                                       | License |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------ | ------- |
| `openpgp.min.js`              | <https://github.com/openpgpjs/openpgpjs/releases> (assets: `openpgp.min.js`, latest 5.x)                      | LGPL-3  |
| `hash-wasm.umd.min.js`        | <https://cdn.jsdelivr.net/npm/hash-wasm@4/dist/index.umd.min.js> (rename to `hash-wasm.umd.min.js`)           | MIT     |

Both are loaded as classic scripts in `index.html` and expose globals
`openpgp` and `hashwasm`. After fetching, no further build step is needed.

If you forget to populate this directory the SPA will boot but Argon2id
falls back to PBKDF2 (with a console warning) and OpenPGP operations will
fail outright.
