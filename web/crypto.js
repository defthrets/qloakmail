// Argon2id key derivation + AES-256-GCM wrapping for the user's
// OpenPGP private key blob.
//
// The hash-wasm UMD bundle exposes `hashwasm` on window. If that fails to
// load (e.g. you forgot to vendor lib/hash-wasm.umd.min.js), we fall back
// to PBKDF2-SHA256 — which is weaker, but lets the SPA boot. The fallback
// is logged with a clear warning.

const ARGON2_DEFAULTS = {
    type: "argon2id",
    memory_kib: 65536,    // 64 MiB
    iterations: 3,
    parallelism: 1,
};

function b64encode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
}
function b64decode(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function randomBytes(n) {
    const out = new Uint8Array(n);
    crypto.getRandomValues(out);
    return out;
}

async function deriveKey(password, params) {
    const salt = b64decode(params.salt_b64);
    const enc = new TextEncoder().encode(password);

    if (typeof window !== "undefined" && window.hashwasm && window.hashwasm.argon2id) {
        const hashHex = await window.hashwasm.argon2id({
            password: enc,
            salt,
            parallelism: params.parallelism,
            iterations: params.iterations,
            memorySize: params.memory_kib,
            hashLength: 32,
            outputType: "hex",
        });
        return hexToBytes(hashHex);
    }

    console.warn("[QloakMail] hash-wasm not available, falling back to PBKDF2 — vendor lib/hash-wasm.umd.min.js for production");
    const baseKey = await crypto.subtle.importKey(
        "raw", enc, { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
        baseKey, 256
    );
    return new Uint8Array(bits);
}

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

/** Wrap (encrypt) the OpenPGP private key blob with the password-derived key. */
export async function wrapPrivateKey(privkeyArmored, password, params = null) {
    const argon = params || {
        ...ARGON2_DEFAULTS,
        salt_b64: b64encode(randomBytes(16)),
    };
    const key = await crypto.subtle.importKey(
        "raw", await deriveKey(password, argon),
        { name: "AES-GCM" }, false, ["encrypt"]
    );
    const iv = randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(privkeyArmored),
    ));
    // Format: 1-byte version | 12-byte iv | ciphertext
    const blob = new Uint8Array(1 + iv.length + ct.length);
    blob[0] = 1;
    blob.set(iv, 1);
    blob.set(ct, 1 + iv.length);
    return { blobB64: b64encode(blob), argon2_params: argon };
}

export async function unwrapPrivateKey(blobB64, password, params) {
    const blob = b64decode(blobB64);
    if (blob[0] !== 1) throw new Error("unsupported wrapped-key format");
    const iv = blob.slice(1, 13);
    const ct = blob.slice(13);
    const key = await crypto.subtle.importKey(
        "raw", await deriveKey(password, params),
        { name: "AES-GCM" }, false, ["decrypt"]
    );
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
}

/** Generate a 24-char human-readable recovery code, grouped 4-4-4-4-4-4. */
export function generateRecoveryCode() {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no 0/O/I/1
    const n = 24;
    const buf = randomBytes(n);
    let out = "";
    for (let i = 0; i < n; i++) {
        if (i > 0 && i % 4 === 0) out += "-";
        out += alphabet[buf[i] % alphabet.length];
    }
    return out;
}

export const _internals = { b64encode, b64decode, randomBytes };
