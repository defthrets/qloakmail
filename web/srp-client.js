// SRP-6a client. RFC 5054 group 2048-bit, SHA-256.
// Must agree byte-for-byte with api/app/srp.py.
//
// Padding rule: every value passed to a hash that is "padded to N" is
// left-padded with zero bytes to len(N) (256 bytes for the 2048-bit group).
// Email is normalized to .trim().toLowerCase() before hashing.

const N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

const N = BigInt("0x" + N_HEX);
const g = 2n;
const N_BYTES = 256;

// ----------------- bytes / hex / bigint helpers -----------------

function hexToBytes(hex) {
    if (hex.startsWith("0x")) hex = hex.slice(2);
    if (hex.length % 2) hex = "0" + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
}

function bigIntToBytes(n, length = N_BYTES) {
    if (n < 0n) throw new Error("negative bigint");
    const bytes = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    if (n !== 0n) throw new Error("bigint larger than length");
    return bytes;
}

function pad(bytes) {
    if (bytes.length === N_BYTES) return bytes;
    if (bytes.length > N_BYTES) throw new Error("value larger than N");
    const out = new Uint8Array(N_BYTES);
    out.set(bytes, N_BYTES - bytes.length);
    return out;
}

function concat(...arrs) {
    let n = 0;
    for (const a of arrs) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
}

async function sha256(...chunks) {
    const buf = concat(...chunks);
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return new Uint8Array(digest);
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
}

// ----------------- modular exponentiation (square-and-multiply) -----------------

function modPow(base, exp, mod) {
    let result = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % mod;
        exp >>= 1n;
        base = (base * base) % mod;
    }
    return result;
}

// ----------------- SRP primitives -----------------

// k = H(N | PAD(g))
let _k = null;
async function getK() {
    if (_k !== null) return _k;
    const h = await sha256(pad(bigIntToBytes(N)), pad(bigIntToBytes(g)));
    _k = bytesToBigInt(h);
    return _k;
}

// x = H(salt | H(I | ":" | password))
async function computeX(saltBytes, identity, password) {
    const enc = new TextEncoder();
    const inner = await sha256(enc.encode(identity + ":" + password));
    const x = await sha256(saltBytes, inner);
    return bytesToBigInt(x);
}

function normalizeIdentity(email) {
    return email.trim().toLowerCase();
}

function randomBytes(n = 32) {
    const out = new Uint8Array(n);
    crypto.getRandomValues(out);
    return out;
}

// ----------------- registration -----------------

/**
 * Generate a brand-new SRP credential (salt + verifier).
 * Returns { saltHex, verifierHex }.
 */
export async function generateVerifier(email, password) {
    const salt = randomBytes(16);
    const x = await computeX(salt, normalizeIdentity(email), password);
    const v = modPow(g, x, N);
    return {
        saltHex: bytesToHex(salt),
        verifierHex: bytesToHex(bigIntToBytes(v)),
    };
}

// ----------------- login -----------------

/**
 * Build a client SRP session. Caller drives:
 *   const session = await SRP.startClient(email, password);
 *   const A = session.getA();                     // hex
 *   // call /auth/login/init with email, get back salt and B
 *   const { M1, M2expected } = await session.processChallenge(saltHex, BHex);
 *   // call /auth/login/verify with A, M1, get back srp_M2
 *   if (!session.verifyServer(M2hex)) throw new Error("server proof invalid");
 *   const sessionKey = session.K;     // shared 32-byte key (not used currently)
 */
export async function startClient(email, password) {
    const identity = normalizeIdentity(email);
    const aBytes = randomBytes(32);
    const a = bytesToBigInt(aBytes) % N;
    const A = modPow(g, a, N);
    const A_bytes = pad(bigIntToBytes(A));

    let M1, M2expected, K;

    return {
        getA: () => bytesToHex(A_bytes),

        async processChallenge(saltHex, BHex) {
            const salt = hexToBytes(saltHex);
            const B = bytesToBigInt(hexToBytes(BHex));
            if (B % N === 0n) throw new Error("invalid B");

            const B_bytes = pad(bigIntToBytes(B));
            const u = bytesToBigInt(await sha256(A_bytes, B_bytes));
            if (u === 0n) throw new Error("invalid u");

            const x = await computeX(salt, identity, password);
            const k = await getK();
            // S = (B - k * g^x) ^ (a + u * x) mod N
            const gx = modPow(g, x, N);
            let inner = (B - (k * gx) % N) % N;
            if (inner < 0n) inner += N;
            const S = modPow(inner, a + u * x, N);
            K = await sha256(bigIntToBytes(S));

            // M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
            const HN = await sha256(bigIntToBytes(N));
            const Hg = await sha256(bigIntToBytes(g));
            const HNxorHg = new Uint8Array(HN.length);
            for (let i = 0; i < HN.length; i++) HNxorHg[i] = HN[i] ^ Hg[i];
            const HI = await sha256(new TextEncoder().encode(identity));

            M1 = await sha256(HNxorHg, HI, salt, A_bytes, B_bytes, K);
            M2expected = await sha256(A_bytes, M1, K);

            return { M1Hex: bytesToHex(M1) };
        },

        verifyServer(M2hex) {
            const m2 = hexToBytes(M2hex);
            return constantTimeEqual(m2, M2expected);
        },

        get K() { return K; },
    };
}
