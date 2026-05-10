// QloakMail SPA entry. ES module.
//
// Auth -> Signup -> Mail. All decryption is local; the server only ever
// sees ciphertext (mailbox blobs) and the SRP verifier (never the password).

import { api } from "/api.js";
import * as SRP from "/srp-client.js";
import {
    wrapPrivateKey, unwrapPrivateKey,
    generateRecoveryCode, _internals,
} from "/crypto.js";
import * as Search from "/search.js";

const { b64encode, b64decode } = _internals;

// Text-only folder icons (no emojis per house style).
const FOLDER_ICONS = {
    inbox:  "▼",
    sent:   "▶",
    drafts: "●",
    trash:  "▪",
    spam:   "▲",
};
const FOLDER_FALLBACK_ICON = "·";

// ----------------------------------------------------------------- state
const state = {
    config: null,
    account: null,           // { account_id, email }
    pubkey: null,            // openpgp.PublicKey
    privkey: null,           // openpgp.PrivateKey, decrypted
    folders: [],
    activeFolderId: null,
    messages: [],
    selectedMessageId: null,
    searchActive: false,
    searchTimer: null,
    // Multi-select & filtering ------------------------------------
    selectedIds: new Set(),  // bulk-action selection
    sortBy: "date-desc",     // "date-desc" | "date-asc" | "from" | "subject" | "unread-first"
    filterBy: "all",         // "all" | "unread" | "starred"
    // Reader view mode --------------------------------------------
    readerMode: "decoded",   // "decoded" | "raw"
    readerRaw: "",           // raw decrypted RFC822 (for raw view)
    readerParsed: null,      // parsed object (for re-render on toggle)
    readerMsgId: null,
};

// User preferences live in localStorage so they survive logout/reload.
const PREFS_KEY = "qloakmail.prefs";
const DEFAULT_PREFS = {
    signature: "",
    density: "comfortable",   // "comfortable" | "compact"
    notifications: false,
    avatar: "",               // base64 data URL of user-set display picture
};
function loadPrefs() {
    try {
        return { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem(PREFS_KEY) || "{}") };
    } catch { return { ...DEFAULT_PREFS }; }
}
function savePrefs(p) {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
    applyPrefsToDom();
}
function applyPrefsToDom() {
    const p = loadPrefs();
    document.body.classList.toggle("density-compact", p.density === "compact");
}

// ----------------------------------------------------------------- helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ----------------------------------------------------------------- session storage
//
// We persist the bits required to unlock a returning user without re-doing
// the SRP handshake: the session token, the *encrypted* private-key blob,
// the Argon2id parameters, the public key, and the account email. The
// PLAINTEXT private key is NEVER persisted — it stays in memory only and
// is re-derived from the user's password on each unlock. Same model as
// Proton Mail: the API session can survive a refresh, but reading mail
// always requires the password (locally, against the encrypted blob).
//
// "Remember on this device" picks the storage:
//   * checked   → localStorage (survives browser close)
//   * unchecked → sessionStorage (survives refresh, clears on tab close)
//
// On logout we clear both.

const SESSION_KEY = "qloakmail.session.v2";
const LEGACY_SESSION_KEYS = ["qloakmail.session.v1"];

const DURATION_MS = {
    "":    0,                   // session-only, password re-prompt on refresh
    "4h":  4    * 60 * 60 * 1000,
    "1d":  24   * 60 * 60 * 1000,
    "1w":  7    * 24 * 60 * 60 * 1000,
    "1mo": 30   * 24 * 60 * 60 * 1000,
};

function durationMs(d) { return DURATION_MS[d] || 0; }

/**
 * Persist what we need to come back on refresh without re-doing the SRP
 * handshake. There are two modes:
 *
 *   duration === ""   → sessionStorage, ENCRYPTED privkey blob only.
 *                       The plaintext privkey is NEVER persisted; the
 *                       unlock-view will ask for the password and run
 *                       Argon2id locally to recover it.
 *
 *   duration !== ""   → localStorage, includes the DECRYPTED privkey
 *                       and an absolute expires_at timestamp. While the
 *                       window is open, refresh = straight to inbox,
 *                       no password prompt. After expiry it falls back
 *                       to the unlock-view.
 *
 * Persisting the plaintext privkey IS a real trade-off — anyone with
 * read access to localStorage can decrypt your mail. Same threat model
 * as any "stay signed in" feature.
 */
function saveSession(data, duration, privkeyArmored) {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
    LEGACY_SESSION_KEYS.forEach(k => {
        sessionStorage.removeItem(k);
        localStorage.removeItem(k);
    });

    const ms = durationMs(duration);
    const payload = { ...data, v: 2, remember: duration };
    if (ms > 0 && privkeyArmored) {
        payload.privkey_armored = privkeyArmored;
        payload.expires_at = Date.now() + ms;
    }
    const target = ms > 0 ? localStorage : sessionStorage;
    target.setItem(SESSION_KEY, JSON.stringify(payload));
}

function loadSession() {
    const raw = localStorage.getItem(SESSION_KEY)
             || sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    try {
        const obj = JSON.parse(raw);
        if (obj && (obj.v === 2 || obj.v === 1) && obj.session_token && obj.email) {
            return obj;
        }
    } catch { /* fall through */ }
    return null;
}

function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);
    LEGACY_SESSION_KEYS.forEach(k => {
        sessionStorage.removeItem(k);
        localStorage.removeItem(k);
    });
}

/** Returns {kind: "auth" | "unlock" | "restore", session?} */
function classifyStoredSession() {
    const sess = loadSession();
    if (!sess) return { kind: "auth" };
    if (sess.expires_at && sess.privkey_armored) {
        if (sess.expires_at > Date.now()) {
            return { kind: "restore", session: sess };
        }
        // Expired — wipe and force unlock if we have the encrypted blob
        // to ask the password against, otherwise force full sign-in.
        if (sess.encrypted_privkey_password) {
            // Drop the now-stale plaintext key but keep the rest for
            // unlock to work against the encrypted blob.
            const { privkey_armored, expires_at, ...minimal } = sess;
            sessionStorage.removeItem(SESSION_KEY);
            localStorage.setItem(SESSION_KEY, JSON.stringify(minimal));
            return { kind: "unlock", session: minimal };
        }
        clearSession();
        return { kind: "auth" };
    }
    return { kind: "unlock", session: sess };
}

const MATRIX_VIEWS = new Set([
    "auth-view", "unlock-view",
    "about-view", "privacy-view", "terms-view",
    "mail-view", "recovery-shown-view",
]);
function show(viewId) {
    $$(".view").forEach(v => v.classList.toggle("active", v.id === viewId));
    // Matrix rain stays on across every view so the cyberpunk
    // backdrop is consistent. Mail-view tones it down via .in-mail
    // so it doesn't compete with the actual content.
    document.body.classList.toggle("matrix-on", MATRIX_VIEWS.has(viewId));
    document.body.classList.toggle("in-mail", viewId === "mail-view");
}

function setStatus(el, text, kind = "") {
    el.textContent = text;
    el.className = "status" + (kind ? " " + kind : "");
}

let _toastTimer;
function toast(text, kind = "") {
    const el = $("#toast");
    el.textContent = text;
    el.className = "toast" + (kind ? " " + kind : "");
    el.hidden = false;
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => { el.hidden = true; }, 4000);
}

function fmtRelative(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d)) return "";
    const sec = (Date.now() - d.getTime()) / 1000;
    if (sec < 60) return "just now";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    if (sec < 86400 * 7) return Math.floor(sec / 86400) + "d";
    return d.toLocaleDateString();
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

// ----------------------------------------------------------------- auth tabs
function bindAuthTabs() {
    $$(".auth-tabs .tab").forEach(btn => {
        btn.addEventListener("click", () => activateAuthTab(btn.dataset.tab));
    });
    // The recovery flow is no longer a top-level tab — it's surfaced
    // as a small "Forgot?" link near the duration row.
    $$(".recovery-link[data-tab]").forEach(btn => {
        btn.addEventListener("click", () => activateAuthTab(btn.dataset.tab));
    });
}

function activateAuthTab(target) {
    if (!target) return;
    $$(".auth-tabs .tab").forEach(b =>
        b.classList.toggle("active", b.dataset.tab === target));
    $$(".auth-form").forEach(f =>
        f.classList.toggle("active", f.id === target + "-form"));
}

// ----------------------------------------------------------------- login (shared)
//
// `duration` is one of "" | "4h" | "1d" | "1w" | "1mo".
// Empty → sessionStorage with encrypted blob, password re-prompt on refresh.
// Anything else → localStorage with decrypted privkey + expires_at, refresh
// inside the window restores directly to the inbox.
async function performLogin(email, password, duration = "") {
    const init = await api.post("/auth/login/init", { email });
    const session = await SRP.startClient(email, password);
    const { M1Hex } = await session.processChallenge(init.srp_salt, init.srp_B);
    const A = session.getA();
    const v = await api.post("/auth/login/verify", {
        session_id: init.session_id,
        srp_A: A,
        srp_M1: M1Hex,
    });
    if (!session.verifyServer(v.srp_M2)) {
        throw new Error("server proof failed — possible MITM");
    }
    const privArmored = await unwrapPrivateKey(
        v.encrypted_privkey_password, password, v.argon2_params
    );
    api.setToken(v.session_token);
    state.account = { account_id: v.account_id, email: v.email };
    state.pubkey = await openpgp.readKey({ armoredKey: v.pubkey_armored });
    state.privkey = await openpgp.readPrivateKey({ armoredKey: privArmored });

    saveSession({
        email: v.email,
        account_id: v.account_id,
        session_token: v.session_token,
        pubkey_armored: v.pubkey_armored,
        encrypted_privkey_password: v.encrypted_privkey_password,
        argon2_params: v.argon2_params,
    }, duration, privArmored);

    await enterMailbox();
}

async function handleLogin(form) {
    const status = $("#login-status");
    const fd = new FormData(form);
    const email = fd.get("email").trim();
    const password = fd.get("password");
    const duration = (fd.get("remember") || "").toString();

    setStatus(status, "Authenticating...");
    try {
        await performLogin(email, password, duration);
    } catch (e) {
        console.error(e);
        setStatus(status, "Sign-in failed: " + (e.message || e), "err");
    }
}

// Restore a session previously saved by performLogin. Re-runs the
// Argon2id derivation locally against the user-typed password to
// decrypt the privkey blob. Does NOT touch the SRP endpoints.
//
// If the original sign-in chose a duration > session, this also re-
// upgrades the storage to include the freshly-decrypted privkey so
// subsequent refreshes within the window go straight to inbox.
async function unlockSession(password) {
    const sess = loadSession();
    if (!sess) throw new Error("no stored session");

    const privArmored = await unwrapPrivateKey(
        sess.encrypted_privkey_password, password, sess.argon2_params
    );

    api.setToken(sess.session_token);
    state.account = { account_id: sess.account_id, email: sess.email };
    state.pubkey = await openpgp.readKey({ armoredKey: sess.pubkey_armored });
    state.privkey = await openpgp.readPrivateKey({ armoredKey: privArmored });

    // Refresh the persistence with the just-decrypted key so subsequent
    // refreshes within the chosen duration window skip the unlock step.
    if (sess.remember && sess.remember !== "") {
        saveSession({
            email: sess.email,
            account_id: sess.account_id,
            session_token: sess.session_token,
            pubkey_armored: sess.pubkey_armored,
            encrypted_privkey_password: sess.encrypted_privkey_password,
            argon2_params: sess.argon2_params,
        }, sess.remember, privArmored);
    }

    // Quick liveness check — if the stored session_token is expired the
    // first call to /users/me will 401. Catching it here lets us drop
    // the stale session and route the user back to the login form.
    try {
        await api.get("/users/me");
    } catch (e) {
        if (e.status === 401) {
            clearSession();
            api.setToken(null);
            state.account = state.privkey = state.pubkey = null;
            throw new Error("session expired — please sign in again");
        }
        // Other errors (network, 5xx) — let enterMailbox surface them.
    }

    await enterMailbox();
}

// ----------------------------------------------------------------- password rules
// Cheap client-side strength check for signups + password reset. Server
// can't reasonably enforce this because we never see the plaintext (SRP
// verifier only), so this is the only gate. Audit v2 (M5).
const WEAK_PASSWORDS = new Set([
    "password1234", "qwerty123456", "letmein12345!", "welcome12345",
    "123456789012", "qloakmail2026", "ChangeMe1234!", "Password1234",
    "passwordpassword", "iloveyou1234", "111111111111", "abcdefghijkl",
]);

function validatePasswordStrength(pw, email) {
    if (typeof pw !== "string" || pw.length < 12) {
        return "Password must be at least 12 characters.";
    }
    if (pw.length > 256) {
        return "Password is unreasonably long (max 256 chars).";
    }
    const classes =
        (/[a-z]/.test(pw) ? 1 : 0) +
        (/[A-Z]/.test(pw) ? 1 : 0) +
        (/[0-9]/.test(pw) ? 1 : 0) +
        (/[^A-Za-z0-9]/.test(pw) ? 1 : 0);
    if (classes < 3) {
        return "Use at least 3 of: lower, upper, digit, symbol.";
    }
    if (WEAK_PASSWORDS.has(pw.toLowerCase())) {
        return "Password is on a well-known weak list. Pick another.";
    }
    if (email) {
        const local = String(email).split("@")[0].toLowerCase();
        if (local && local.length >= 4 && pw.toLowerCase().includes(local)) {
            return "Password must not contain your email.";
        }
    }
    // Final gate: even after meeting the structural rules above, the
    // password must score at least "Good" (>= 55) on the live meter.
    // This catches structurally-valid-but-low-entropy passwords like
    // "Passsword1234" (3 classes, 12 chars, not weak-listed, still
    // trivial) and anything with long character runs.
    const { tier } = scorePassword(pw, email);
    if (tier !== "good" && tier !== "strong") {
        return "Password is not strong enough — aim for 'Good' or 'Strong' on the meter (more length, more variety, no repetition).";
    }
    return null;
}

// Live strength score: returns { score:0..100, tier:'toolow'|...|'strong',
// label } so the meter UI and the submit gate share one source of
// truth. Scoring is deliberately simple (no zxcvbn dependency); it
// rewards length, character-class variety, and uncommon shapes, and
// penalises the well-known weak list and email-substring presence.
function scorePassword(pw, email) {
    if (!pw) return { score: 0, tier: "toolow", label: "Type a password" };
    if (pw.length < 12) {
        return { score: Math.round((pw.length / 12) * 20),
                 tier: "toolow", label: "Too short" };
    }
    let s = 0;
    // Length: 12 chars -> 20pts, then +3 per extra char up to 28 chars -> 68pts.
    s += 20 + Math.min(48, Math.max(0, (pw.length - 12) * 3));
    // Character-class variety: 6pts each.
    s += (/[a-z]/.test(pw) ? 6 : 0);
    s += (/[A-Z]/.test(pw) ? 6 : 0);
    s += (/[0-9]/.test(pw) ? 6 : 0);
    s += (/[^A-Za-z0-9]/.test(pw) ? 6 : 0);
    // Bonus: long passwords with all four classes get a small kicker.
    if (pw.length >= 20 && /[a-z]/.test(pw) && /[A-Z]/.test(pw)
        && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s += 10;
    // Penalties.
    if (WEAK_PASSWORDS.has(pw.toLowerCase())) s -= 60;
    if (email) {
        const local = String(email).split("@")[0].toLowerCase();
        if (local && local.length >= 4 && pw.toLowerCase().includes(local)) s -= 30;
    }
    // Trivial-repetition penalties.
    //   Whole-string single-char (aaaa...)        -> -60
    //   Whole-string ababab... or abcabcabc...    -> -40
    //   Any run of 5+ identical chars inside pw   -> -25 (catches
    //                                                  e.g. aaaaaA1!)
    //   Sequential keyboard/number run length >=5 -> -15
    if (/^(.)\1+$/.test(pw)) s -= 60;
    if (/^(..?)\1{3,}$/.test(pw)) s -= 40;
    if (/(.)\1{4,}/.test(pw)) s -= 25;
    if (/01234|12345|23456|34567|45678|56789|abcde|bcdef|cdefg|defgh|qwert|werty/i.test(pw)) s -= 15;
    s = Math.max(0, Math.min(100, s));

    // Lenient thresholds: each tier shifts down so passwords feel
    // achievable without being permissive of the well-known patterns
    // the penalties already strip out.
    //   weak   < 20  -- red
    //   fair   20-39 -- orange
    //   good   40-54 -- yellow
    //   strong 55+   -- green
    let tier, label;
    if      (s < 20)  { tier = "weak";   label = "Weak"; }
    else if (s < 40)  { tier = "fair";   label = "Fair"; }
    else if (s < 55)  { tier = "good";   label = "Good"; }
    else              { tier = "strong"; label = "Strong"; }
    return { score: s, tier, label };
}

// Wire a .pw-strength wrapper to its referenced password input. Updates
// the bar width + colour + label on every input event. Idempotent --
// calling twice on the same wrapper just re-binds.
function bindPasswordStrength(wrapper, getEmail) {
    if (!wrapper || wrapper._bound) return;
    const targetId = wrapper.dataset.for;
    const input = document.getElementById(targetId);
    if (!input) return;
    const fill  = wrapper.querySelector(".pw-strength-fill");
    const label = wrapper.querySelector(".pw-strength-label");
    const tiers = ["toolow", "weak", "fair", "good", "strong"];
    const update = () => {
        const email = typeof getEmail === "function" ? getEmail() : "";
        const { score, tier, label: text } = scorePassword(input.value, email);
        fill.style.width = score + "%";
        label.textContent = text;
        tiers.forEach(t => wrapper.classList.toggle("t-" + t, t === tier));
    };
    input.addEventListener("input", update);
    wrapper._bound = true;
    update();
}

// ----------------------------------------------------------------- signup
async function handleSignup(form) {
    const status = $("#signup-status");
    setStatus(status, "Generating keypair (this can take a few seconds)...");

    const fd = new FormData(form);
    // Username-only signup: the user picks the local-part, the domain
    // suffix is locked to the primary configured domain. Strip any
    // accidental @-suffix the user typed (e.g. pasted full address)
    // and lowercase so the verifier identity is canonical.
    const primaryDomain = (state.config?.domain || "qloak.me").toLowerCase();
    let username = (fd.get("username") || "").trim().toLowerCase();
    if (username.includes("@")) username = username.split("@")[0];
    if (!/^[a-z0-9._-]{1,64}$/.test(username)) {
        setStatus(status, "Username can only contain a-z, 0-9, dot, underscore, or hyphen (1-64 chars).", "err");
        return;
    }
    const email = `${username}@${primaryDomain}`;
    const password = fd.get("password");
    const password2 = fd.get("password2");
    const invite = (fd.get("invite") || "").trim();

    if (password !== password2) {
        setStatus(status, "Passwords do not match.", "err");
        return;
    }

    // Password complexity — audit v2 (M5). Floor of 12 chars is also
    // enforced by minlength= on the input, but we re-check here so
    // pasted whitespace + variety rules can't be bypassed. Rules:
    //   1. >= 12 characters
    //   2. >= 3 of: lowercase, uppercase, digit, symbol
    //   3. not in the small in-memory list of well-known weak passwords
    const pwIssue = validatePasswordStrength(password, email);
    if (pwIssue) { setStatus(status, pwIssue, "err"); return; }

    try {
        const { privateKey, publicKey } = await openpgp.generateKey({
            type: "ecc",
            curve: "ed25519",
            userIDs: [{ email }],
            format: "armored",
        });
        const pubObj = await openpgp.readKey({ armoredKey: publicKey });
        const fpr = pubObj.getFingerprint();

        const recoveryCode = generateRecoveryCode();

        const wrappedPwd = await wrapPrivateKey(privateKey, password);
        const wrappedRec = await wrapPrivateKey(privateKey, recoveryCode, {
            ...wrappedPwd.argon2_params,
            salt_b64: b64encode(_internals.randomBytes(16)),
        });

        const { saltHex, verifierHex } = await SRP.generateVerifier(email, password);

        setStatus(status, "Submitting registration...");
        await api.post("/auth/register", {
            email,
            srp_salt: saltHex,
            srp_verifier: verifierHex,
            pubkey_armored: publicKey,
            pubkey_fpr: fpr,
            encrypted_privkey_password: wrappedPwd.blobB64,
            encrypted_privkey_recovery: wrappedRec.blobB64,
            argon2_params: wrappedPwd.argon2_params,
            invite_code: invite || null,
            captcha_token: null,
        });

        // Show recovery code, then auto-login on confirm.
        const codeEl = $("#recovery-shown-code");
        codeEl.textContent = recoveryCode;
        // Auto-clear the clipboard 30s after the user copies the
        // recovery code, so it doesn't sit in the OS paste buffer.
        codeEl.addEventListener("copy", scheduleClipboardClear, { once: true });
        show("recovery-shown-view");

        const confirmBox = $("#recovery-shown-confirm");
        const continueBtn = $("#recovery-shown-continue");
        const recoveryStatus = $("#recovery-shown-status");

        confirmBox.checked = false;
        continueBtn.disabled = true;
        setStatus(recoveryStatus, "");

        confirmBox.onchange = e => { continueBtn.disabled = !e.target.checked; };
        continueBtn.onclick = async () => {
            continueBtn.disabled = true;
            setStatus(recoveryStatus, "Signing you in...");
            try {
                // Just-created accounts default to remember-on-this-device.
                await performLogin(email, password, "1mo");
            } catch (e) {
                console.error("[QloakMail] auto-login after signup failed:", e);
                setStatus(recoveryStatus, "Auto sign-in failed. Use the form below.", "err");
                show("auth-view");
                $("#login-form input[name=email]").value = email;
                $("#login-form input[name=password]").focus();
            }
        };
    } catch (e) {
        console.error(e);
        setStatus(status, "Failed: " + (e.message || e), "err");
    }
}

// ----------------------------------------------------------------- recovery
async function handleRecovery(form) {
    const status = $("#recovery-status");
    const fd = new FormData(form);
    const email = fd.get("email").trim();
    const recoveryCode = fd.get("recovery").trim();
    const newPassword = fd.get("password");

    const pwIssue = validatePasswordStrength(newPassword, email);
    if (pwIssue) { setStatus(status, pwIssue, "err"); return; }

    setStatus(status, "Verifying recovery code...");
    try {
        const r = await api.post("/auth/recovery", { email });
        const privArmored = await unwrapPrivateKey(
            r.encrypted_privkey_recovery, recoveryCode, r.argon2_params
        );

        const wrappedPwd = await wrapPrivateKey(privArmored, newPassword);
        const wrappedRec = await wrapPrivateKey(privArmored, recoveryCode, {
            ...wrappedPwd.argon2_params,
            salt_b64: b64encode(_internals.randomBytes(16)),
        });
        const { saltHex, verifierHex } = await SRP.generateVerifier(email, newPassword);

        await api.post("/auth/reset-password", {
            email,
            srp_salt: saltHex,
            srp_verifier: verifierHex,
            pubkey_armored: r.pubkey_armored,
            pubkey_fpr: (await openpgp.readKey({ armoredKey: r.pubkey_armored })).getFingerprint(),
            encrypted_privkey_password: wrappedPwd.blobB64,
            encrypted_privkey_recovery: wrappedRec.blobB64,
            argon2_params: wrappedPwd.argon2_params,
        });

        setStatus(status, "Recovered. Signing you in...", "ok");
        try {
            // Recovery flow defaults to NOT remembering — recovery is
            // commonly run from an unfamiliar device.
            await performLogin(email, newPassword, false);
        } catch (e) {
            console.error(e);
            setStatus(status, "Password reset, please sign in.", "ok");
            $$(".auth-tabs .tab").forEach(b => b.classList.toggle("active", b.dataset.tab === "login"));
            $$(".auth-form").forEach(f => f.classList.toggle("active", f.id === "login-form"));
            $("#login-form input[name=email]").value = email;
        }
    } catch (e) {
        console.error(e);
        setStatus(status, "Recovery failed: " + (e.message || e), "err");
    }
}

// ----------------------------------------------------------------- mobile chrome
//
// Phone (≤640px) layout collapses the sidebar to a 56px icon rail and
// hides the reader pane. This binds:
//   * #sidebar-toggle -> body.sidebar-open    (hamburger pop-out)
//   * tap on the scrim ::before               (close sidebar)
//   * folder pick                             (auto-close sidebar)
//   * .reader-close button                    (close the reader popup)
//   * Escape key                              (close whichever is open)
//
// Idempotent: enterMailbox() may be called multiple times; we only
// attach handlers once, gated by a flag.
let _mailMobileBound = false;
function bindMailMobile() {
    if (_mailMobileBound) return;
    _mailMobileBound = true;

    const toggle = document.getElementById("sidebar-toggle");
    if (toggle) {
        toggle.addEventListener("click", (e) => {
            e.stopPropagation();
            const open = document.body.classList.toggle("sidebar-open");
            toggle.setAttribute("aria-expanded", open ? "true" : "false");
        });
    }

    // Tapping the scrim (the ::before on .mail-shell) closes the
    // sidebar. The pseudo-element catches clicks because of pointer-
    // events default on positioned elements with content.
    document.addEventListener("click", (e) => {
        if (!document.body.classList.contains("sidebar-open")) return;
        // Click was inside the sidebar or on the toggle? leave open.
        if (e.target.closest(".sidebar")) return;
        if (e.target.closest("#sidebar-toggle")) return;
        document.body.classList.remove("sidebar-open");
        toggle?.setAttribute("aria-expanded", "false");
    });

    // Reader popup close — listener delegated on #message-view because
    // the close button is rendered fresh by openMessage() each time.
    const view = document.getElementById("message-view");
    if (view) {
        view.addEventListener("click", (e) => {
            if (e.target.closest(".reader-close")) {
                view.classList.remove("open");
            }
        });
    }

    // Escape closes whichever overlay is on.
    document.addEventListener("keydown", (e) => {
        if (e.key !== "Escape") return;
        if (document.body.classList.contains("sidebar-open")) {
            document.body.classList.remove("sidebar-open");
            toggle?.setAttribute("aria-expanded", "false");
            return;
        }
        if (view?.classList.contains("open")) {
            view.classList.remove("open");
        }
    });
}

// ----------------------------------------------------------------- mailbox
async function enterMailbox() {
    show("mail-view");
    $("#who").textContent = state.account.email;
    armIdleLock();
    bindMailMobile();
    refreshAdminGate();
    try {
        await Search.open(state.account.account_id);
        await refreshSearchStats();
    } catch (e) {
        console.warn("[QloakMail] search index unavailable:", e);
    }
    try {
        await loadFolders();
        if (state.folders.length) {
            const inbox = state.folders.find(f => f.system_kind === "inbox") || state.folders[0];
            await selectFolder(inbox.id);
        } else {
            renderEmptyReader();
        }
    } catch (e) {
        console.error("[QloakMail] failed to load mailbox:", e);
        toast("Failed to load mailbox: " + (e.message || e), "err");
        renderEmptyReader();
    }
}

async function refreshSearchStats() {
    try {
        const s = await Search.stats();
        $("#search-stats").textContent = s.messages
            ? `${s.messages} indexed` : "";
    } catch { /* index not open */ }
}

async function loadFolders() {
    state.folders = await api.get("/mail/folders");
    const ul = $("#folder-list");
    ul.innerHTML = "";
    for (const f of state.folders) {
        const li = document.createElement("li");
        const icon = FOLDER_ICONS[f.system_kind] || FOLDER_FALLBACK_ICON;
        const showCount = f.unread_count > 0
            ? f.unread_count
            : (f.total_count || "");
        li.innerHTML = `
            <span><span class="icon">${escapeHtml(icon)}</span>${escapeHtml(f.name)}</span>
            <span class="count">${escapeHtml(String(showCount))}</span>
        `;
        if (f.id === state.activeFolderId) li.classList.add("active");
        li.addEventListener("click", () => selectFolder(f.id));
        ul.appendChild(li);
    }
}

async function selectFolder(folderId) {
    // On mobile: picking a folder dismisses the sidebar overlay.
    document.body.classList.remove("sidebar-open");
    document.getElementById("sidebar-toggle")?.setAttribute("aria-expanded", "false");

    state.activeFolderId = folderId;
    state.selectedMessageId = null;
    $$("#folder-list li").forEach((li, i) =>
        li.classList.toggle("active", state.folders[i]?.id === folderId));

    try {
        state.messages = await api.get(`/mail/folders/${folderId}/messages`);
    } catch (e) {
        console.error(e);
        toast("Failed to load messages: " + (e.message || e), "err");
        state.messages = [];
    }

    state.searchActive = false;
    const input = $("#search-input");
    if (input.value) input.value = "";
    await refreshSearchStats();
    await renderMessageList();
    renderEmptyReader();

    // Kick off a background decrypt of un-cached messages so the list
    // shows real previews instead of locked placeholders. Sequential
    // and yieldy to keep the UI responsive.
    backgroundDecryptUncached().catch(e =>
        console.warn("[QloakMail] bg decrypt task error:", e));
}

let _bgDecryptToken = 0;
async function backgroundDecryptUncached() {
    const token = ++_bgDecryptToken;
    const folderAtStart = state.activeFolderId;

    const cached = await Search.getCachedBatch(state.messages.map(m => m.id));
    const todo = state.messages
        .filter(m => !cached.has(m.id))
        .sort((a, b) =>
            new Date(b.received_at).getTime() - new Date(a.received_at).getTime()
        );
    if (!todo.length) return;

    for (const msg of todo) {
        // Cancel if the user switched folders or logged out.
        if (token !== _bgDecryptToken) return;
        if (state.activeFolderId !== folderAtStart) return;
        if (!state.privkey) return;

        try {
            const r = await api.get(`/mail/messages/${msg.id}`);
            const blob = b64decode(r.encrypted_blob_b64);
            const armored = new TextDecoder().decode(blob);
            const enc = extractPgpPart(armored);
            const message = await openpgp.readMessage({ armoredMessage: enc });
            const { data: bytes } = await openpgp.decrypt({
                message,
                decryptionKeys: state.privkey,
                format: "binary",
            });
            const plaintext = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
            const parsed = parseRfc822(plaintext);
            await Search.indexMessage(msg.id, parsed);

            // Re-render only if still relevant.
            if (token === _bgDecryptToken &&
                state.activeFolderId === folderAtStart &&
                !state.searchActive) {
                await renderMessageList();
            }
        } catch (e) {
            console.warn("[QloakMail] bg decrypt failed for", msg.id, e);
        }
        // Yield so clicks/typing stay snappy between decrypts.
        await new Promise(r => setTimeout(r, 40));
    }
    if (token === _bgDecryptToken) await refreshSearchStats();
}

function renderEmptyReader() {
    $("#message-view").innerHTML = `
        <div class="reader-empty">
            <h3>Select a message</h3>
            <p>Choose an email from the list, or compose a new one.</p>
        </div>
    `;
}

function applyListSortFilter(messages) {
    let out = messages.slice();
    if (state.filterBy === "unread")  out = out.filter(m => !m.flags.includes("\\Seen"));
    if (state.filterBy === "starred") out = out.filter(m =>  m.flags.includes("\\Flagged"));
    const cmp = {
        "date-desc":    (a, b) => new Date(b.received_at) - new Date(a.received_at),
        "date-asc":     (a, b) => new Date(a.received_at) - new Date(b.received_at),
        "unread-first": (a, b) => {
            const ua = a.flags.includes("\\Seen") ? 1 : 0;
            const ub = b.flags.includes("\\Seen") ? 1 : 0;
            return ua - ub || (new Date(b.received_at) - new Date(a.received_at));
        },
    }[state.sortBy] || ((a, b) => new Date(b.received_at) - new Date(a.received_at));
    out.sort(cmp);
    return out;
}

async function renderMessageList() {
    const ul = $("#message-list");
    ul.innerHTML = "";
    refreshBulkBar();

    const messages = applyListSortFilter(state.messages);

    if (!messages.length) {
        const folder = state.folders.find(f => f.id === state.activeFolderId);
        const isInbox = folder?.system_kind === "inbox";
        const userEmail = state.account?.email || "";
        const filterNote = state.filterBy !== "all"
            ? `<p>No <strong>${state.filterBy}</strong> messages in this folder.</p>`
            : "";
        ul.innerHTML = isInbox && state.filterBy === "all" ? `
            <li class="empty-state">
                <h4>Your inbox is empty</h4>
                <p>Have a friend send a test to <code>${escapeHtml(userEmail)}</code> — it'll show up here, decrypted in your browser.</p>
            </li>
        ` : `
            <li class="empty-state">
                <h4>Empty folder</h4>
                ${filterNote || "<p>No messages here yet.</p>"}
            </li>
        `;
        return;
    }

    let cached = new Map();
    try { cached = await Search.getCachedBatch(messages.map(m => m.id)); }
    catch (e) { console.warn("[QloakMail] preview cache unavailable:", e); }

    for (const m of messages) {
        const li = document.createElement("li");
        const isUnread  = !m.flags.includes("\\Seen");
        const isStarred =  m.flags.includes("\\Flagged");
        if (isUnread)  li.classList.add("unread");
        if (isStarred) li.classList.add("starred");
        if (state.selectedIds.has(m.id))         li.classList.add("checked");
        if (m.id === state.selectedMessageId)    li.classList.add("active");

        const c = cached.get(m.id);
        const fromStr     = c?.from    || "(encrypted)";
        const subjectStr  = c?.subject || (c ? "(no subject)" : `${m.size_bytes}b · tap to decrypt`);
        const snippetStr  = c?.snippet || "";
        const when        = c?.date ? fmtRelative(c.date) : fmtRelative(m.received_at);

        const fromForAvatar = c?.from || "";
        const avatarMarkup  = c ? avatarHtml(fromForAvatar, { size: 28 }) : `<span class="avatar avatar-locked" title="encrypted">●</span>`;
        li.innerHTML = `
            <label class="row-check" aria-label="Select message">
                <input type="checkbox" data-msg-id="${m.id}" ${state.selectedIds.has(m.id) ? "checked" : ""}>
            </label>
            <button class="row-star ${isStarred ? "is-starred" : ""}"
                    data-msg-id="${m.id}"
                    aria-label="${isStarred ? "Unstar" : "Star"}"
                    title="${isStarred ? "Unstar" : "Star"}">${isStarred ? "★" : "☆"}</button>
            ${avatarMarkup}
            <div class="row-body">
                <div class="row-top">
                    <span class="from">${c ? escapeHtml(fromStr) : `<span class="enc-tag">[ENCRYPTED]</span>`}</span>
                    <span class="when">${escapeHtml(when)}</span>
                </div>
                <div class="subject ${c ? "" : "muted"}">${escapeHtml(subjectStr)}</div>
                ${c ? `<div class="snippet">${escapeHtml(snippetStr)}</div>` : ""}
            </div>
        `;
        if (!c) li.classList.add("locked");

        // Body click opens the message; checkbox + star don't bubble.
        li.querySelector(".row-body").addEventListener("click", () => openMessage(m.id));
        li.querySelector(".row-check input").addEventListener("change", (e) => {
            e.stopPropagation();
            toggleSelected(m.id, e.target.checked);
        });
        li.querySelector(".row-star").addEventListener("click", (e) => {
            e.stopPropagation();
            toggleStar(m.id);
        });

        ul.appendChild(li);
    }
}

// ----------------------------------------------------------------- list controls
//
// Sort/filter chips above the list, plus the bulk-action bar that
// appears once any rows are checked. Both purely client-side; the
// underlying messages list stays as-is.

function bindListControls() {
    document.querySelectorAll("[data-sort]").forEach(b =>
        b.addEventListener("click", () => {
            state.sortBy = b.dataset.sort;
            document.querySelectorAll("[data-sort]").forEach(o =>
                o.classList.toggle("active", o.dataset.sort === state.sortBy));
            renderMessageList();
        }));
    document.querySelectorAll("[data-filter]").forEach(b =>
        b.addEventListener("click", () => {
            state.filterBy = b.dataset.filter;
            document.querySelectorAll("[data-filter]").forEach(o =>
                o.classList.toggle("active", o.dataset.filter === state.filterBy));
            renderMessageList();
        }));
    $("#select-all")?.addEventListener("change", (e) => {
        const checked = e.target.checked;
        if (checked) {
            applyListSortFilter(state.messages).forEach(m => state.selectedIds.add(m.id));
        } else {
            state.selectedIds.clear();
        }
        renderMessageList();
    });
    $$("[data-bulk]").forEach(b =>
        b.addEventListener("click", () => doBulkAction(b.dataset.bulk)));
}

function toggleSelected(id, on) {
    if (on) state.selectedIds.add(id); else state.selectedIds.delete(id);
    refreshBulkBar();
}

function refreshBulkBar() {
    const bar = $("#bulk-bar");
    if (!bar) return;
    const n = state.selectedIds.size;
    bar.hidden = n === 0;
    const counter = $("#bulk-count");
    if (counter) counter.textContent = String(n);
    const all = $("#select-all");
    if (all) all.checked = n > 0 && n === applyListSortFilter(state.messages).length;
}

async function doBulkAction(action) {
    const ids = [...state.selectedIds];
    if (!ids.length) return;
    let ok = 0, fail = 0;
    setStatus($("#compose-status") || document.createElement("div"), ""); // no-op safety
    for (const id of ids) {
        try {
            if (action === "delete" || action === "spam") {
                if (action === "spam") {
                    try { await api.post(`/mail/messages/${id}/flags`, { add: ["\\Junk"], remove: [] }); }
                    catch {}
                }
                await api.del(`/mail/messages/${id}`);
                try { await Search.forget(id); } catch {}
                state.messages = state.messages.filter(m => m.id !== id);
            } else if (action === "read")    await setSeen(id, true);
            else if (action === "unread")    await setSeen(id, false);
            else if (action === "star")      await setStar(id, true);
            else if (action === "unstar")    await setStar(id, false);
            ok++;
        } catch (e) {
            console.warn("[QloakMail] bulk", action, id, e);
            fail++;
        }
    }
    state.selectedIds.clear();
    await renderMessageList();
    await loadFolders();
    toast(`${action}: ${ok} done${fail ? `, ${fail} failed` : ""}`, fail ? "err" : "ok");
}

async function openMessage(id) {
    state.selectedMessageId = id;
    // Re-render to set active class on the right li.
    if (!state.searchActive) renderMessageList();

    const view = $("#message-view");
    // Pop the reader as a fullscreen overlay on mobile (CSS handles
    // the actual layout via .reader.open). Harmless on desktop where
    // the reader is always visible.
    view.classList.add("open");
    view.innerHTML = `
        <button class="reader-close" aria-label="Close" type="button">×</button>
        <div class="reader-empty">
            <p>Decrypting...</p>
        </div>
    `;
    try {
        const msg = await api.get(`/mail/messages/${id}`);
        const blob = b64decode(msg.encrypted_blob_b64);
        const armored = new TextDecoder().decode(blob);

        const enc = extractPgpPart(armored);
        const message = await openpgp.readMessage({ armoredMessage: enc });
        // Decrypt to BINARY then decode as UTF-8 ourselves. If we let
        // openpgp.js return a string it interprets the literal-data
        // packet as Latin-1, mangling multi-byte UTF-8 sequences
        // ("don't" -> "donâ€™t" etc).
        const { data: plaintextBytes } = await openpgp.decrypt({
            message,
            decryptionKeys: state.privkey,
            format: "binary",
        });
        const plaintextRfc822 = new TextDecoder("utf-8", { fatal: false })
            .decode(plaintextBytes);

        const parsed = parseRfc822(plaintextRfc822);
        // Fallback: if parsing returned an empty body (unusual MIME
        // structure, transfer-encoding we don't handle), show the raw
        // decrypted source so the user at least sees their mail rather
        // than an empty pane.
        const bodyToRender = parsed.body && parsed.body.trim()
            ? parsed.body
            : plaintextRfc822;
        const liveMsg = state.messages.find(x => x.id === id);
        const isStarred = liveMsg?.flags.includes("\\Flagged");
        const senderAvatar = avatarHtml(parsed.from, { size: 36 });
        const hasHtml      = !!parsed.htmlBody;
        const hasRemote    = hasHtml && htmlBodyHasRemoteImages(parsed.htmlBody);
        const attachments  = parsed.attachments || [];
        // Don't list inline images that DID get resolved into the HTML
        // (they're already shown in the body); keep ones with no cid
        // resolution as standalone attachments.
        const visibleAttachments = attachments.filter(a => !a.cid || !parsed.inlineImages?.has(a.cid));

        view.innerHTML = `
            <button class="reader-close" aria-label="Close" type="button">×</button>
            <header>
                <div class="reader-header-row">
                    ${senderAvatar}
                    <div class="reader-header-text">
                        <h2>${escapeHtml(parsed.subject || "(no subject)")}</h2>
                        <div class="meta">
                            <div><span class="field-tag">[FROM]</span><strong>${escapeHtml(parsed.from || "")}</strong></div>
                            <div><span class="field-tag">[TO]</span><strong>${escapeHtml(parsed.to || "")}</strong></div>
                            ${parsed.cc ? `<div><span class="field-tag">[CC]</span><strong>${escapeHtml(parsed.cc)}</strong></div>` : ""}
                            <div><span class="field-tag">[DATE]</span>${escapeHtml(parsed.date || "")}</div>
                        </div>
                    </div>
                </div>
            </header>
            <div class="reader-actions">
                <button class="reader-action" data-action="reply"      data-label="Reply"      title="Reply" type="button">↩</button>
                <button class="reader-action" data-action="reply-all"  data-label="Reply all"  title="Reply all" type="button">⇇</button>
                <button class="reader-action" data-action="forward"    data-label="Forward"    title="Forward" type="button">↪</button>
                <button class="reader-action" data-action="star"       data-label="${isStarred ? "Unstar" : "Star"}" data-starred="${isStarred ? "1" : "0"}" title="${isStarred ? "Unstar" : "Star"}" type="button">${isStarred ? "★" : "☆"}</button>
                <button class="reader-action" data-action="unread"     data-label="Mark unread" title="Mark unread" type="button">◐</button>
                <button class="reader-action" data-action="print"      data-label="Print"       title="Print" type="button">⎙</button>
                ${hasHtml && parsed.textBody ? `<button class="reader-action" data-action="view-toggle" data-label="Plain text" title="Toggle plain text / HTML" type="button">¶</button>` : ""}
                <button class="reader-action" data-action="raw"        data-label="Raw source"  title="Raw RFC 822 source" type="button">⌭</button>
                <button class="reader-action" data-action="delete"     data-label="Delete"      title="Delete" type="button">⌫</button>
                <button class="reader-action danger" data-action="spam"  data-label="Spam"  title="Mark as spam" type="button">⚠</button>
                <button class="reader-action danger" data-action="block" data-label="Block" title="Block sender" type="button">⊘</button>
            </div>
            ${hasRemote ? `
                <div class="remote-image-banner" id="remote-image-banner">
                    <span><span class="banner-tag">[IMAGES]</span> Remote images blocked for privacy.</span>
                    <button type="button" class="banner-action" data-action="load-images">Load images</button>
                </div>` : ""}
            <div class="body-content"></div>
            ${visibleAttachments.length ? `
                <section class="attachments">
                    <h3><span class="bracket">[</span>ATTACHMENTS<span class="bracket">]</span> <span class="count">${visibleAttachments.length}</span></h3>
                    <ul class="attachment-list">
                        ${visibleAttachments.map((att, i) => `
                            <li>
                                <button class="att-download" data-att-index="${i}" type="button" title="Download">
                                    <span class="att-icon">${_attachmentIcon(att.mime)}</span>
                                    <span class="att-name">${escapeHtml(att.filename)}</span>
                                    <span class="att-meta">${escapeHtml(att.mime || "")} · ${fmtBytes(Math.floor(att.dataB64.length * 0.75))}</span>
                                </button>
                            </li>`).join("")}
                    </ul>
                </section>` : ""}
        `;

        // Render body. HTML preferred when present, sanitised either way.
        const bodyEl = view.querySelector(".body-content");
        if (hasHtml) {
            bodyEl.classList.add("html-body");
            bodyEl.innerHTML = sanitiseHtml(parsed.htmlBody, {
                inlineImages: parsed.inlineImages,
                allowRemoteImages: false,
            });
        } else {
            bodyEl.classList.add("text-body");
            const pre = document.createElement("pre");
            pre.textContent = bodyToRender;
            bodyEl.appendChild(pre);
        }

        // Stash for raw-toggle / view-toggle (no need to re-decrypt).
        state.readerRaw = plaintextRfc822;
        state.readerParsed = parsed;
        state.readerMsgId = id;
        state.readerMode = "decoded";
        state.readerView = hasHtml ? "html" : "text";

        // Wire interactive bits.
        bindReaderActions(view, id, parsed);
        // Attachment downloads.
        view.querySelectorAll(".att-download").forEach(btn => {
            btn.addEventListener("click", () => {
                const i = +btn.dataset.attIndex;
                downloadAttachment(visibleAttachments[i]);
            });
        });
        // Load-remote-images banner.
        view.querySelector('[data-action="load-images"]')?.addEventListener("click", () => {
            bodyEl.innerHTML = sanitiseHtml(parsed.htmlBody, {
                inlineImages: parsed.inlineImages,
                allowRemoteImages: true,
            });
            $("#remote-image-banner")?.remove();
        });

        if (!msg.flags.includes("\\Seen")) {
            await api.post(`/mail/messages/${id}/flags`, { add: ["\\Seen"], remove: [] });
            await loadFolders();
        }

        try {
            await Search.indexMessage(id, parsed);
            await refreshSearchStats();
        } catch (e) {
            console.warn("[QloakMail] indexing failed:", e);
        }
    } catch (e) {
        console.error(e);
        view.innerHTML = `
            <button class="reader-close" aria-label="Close" type="button">×</button>
            <div class="reader-empty">
                <h3>Decryption failed</h3>
                <p>${escapeHtml(e.message || String(e))}</p>
            </div>
        `;
    }
}

// ----------------------------------------------------------------- flag helpers
//
// Thin wrappers over POST /mail/messages/:id/flags that update the
// in-memory state.messages so the UI reflects the change without
// re-fetching the list. Standard IMAP flags:
//   \Seen     — read/unread
//   \Flagged  — starred
//   \Junk     — spam (we tag then delete)
//   \Answered — replied (set after a successful reply)

function _updateLocalFlags(id, add = [], remove = []) {
    const m = state.messages.find(x => x.id === id);
    if (!m) return;
    const set = new Set(m.flags || []);
    add.forEach(f => set.add(f));
    remove.forEach(f => set.delete(f));
    m.flags = [...set];
}

async function setSeen(id, seen) {
    const action = seen
        ? { add: ["\\Seen"], remove: [] }
        : { add: [],          remove: ["\\Seen"] };
    await api.post(`/mail/messages/${id}/flags`, action);
    _updateLocalFlags(id, action.add, action.remove);
}

async function setStar(id, star) {
    const action = star
        ? { add: ["\\Flagged"], remove: [] }
        : { add: [],            remove: ["\\Flagged"] };
    await api.post(`/mail/messages/${id}/flags`, action);
    _updateLocalFlags(id, action.add, action.remove);
}

async function toggleStar(id) {
    const m = state.messages.find(x => x.id === id);
    if (!m) return;
    const isStarred = m.flags.includes("\\Flagged");
    await setStar(id, !isStarred);
    await renderMessageList();
}

async function toggleSeen(id) {
    const m = state.messages.find(x => x.id === id);
    if (!m) return;
    const isSeen = m.flags.includes("\\Seen");
    await setSeen(id, !isSeen);
    await renderMessageList();
    await loadFolders();
}

// ----------------------------------------------------------------- reader actions
//
// Per-message actions: reply, reply-all, forward, delete, spam, block.
// `parsed` is the already-decoded RFC 822 (headers + body) so we can
// build quoted replies and pull the sender for blocklist / reply-to.
//
// reply / reply-all / forward open the compose modal pre-filled.
// delete calls api.del + refreshes the list.
// spam tags the message with \Junk and removes it from the inbox.
// block adds the sender to a per-account localStorage blocklist.

function bindReaderActions(viewEl, msgId, parsed) {
    viewEl.querySelectorAll(".reader-action[data-action]").forEach(btn => {
        btn.addEventListener("click", async () => {
            const action = btn.dataset.action;
            try {
                if (action === "reply")          openReplyCompose(parsed, false);
                else if (action === "reply-all") openReplyCompose(parsed, true);
                else if (action === "forward")   openForwardCompose(parsed);
                else if (action === "delete")    await deleteMessage(msgId);
                else if (action === "spam")      await markSpam(msgId, parsed);
                else if (action === "block")     await blockSender(parsed);
                else if (action === "star")      await readerToggleStar(viewEl, msgId);
                else if (action === "unread")    await readerMarkUnread(msgId);
                else if (action === "print")     printReader();
                else if (action === "raw")       toggleRawView(viewEl);
                else if (action === "view-toggle") toggleHtmlText(viewEl, parsed);
            } catch (e) {
                console.error("[QloakMail] reader action failed:", action, e);
                toast(`${action} failed: ${e.message || e}`, "err");
            }
        });
    });
}

async function readerToggleStar(viewEl, id) {
    const m = state.messages.find(x => x.id === id);
    if (!m) return;
    const isStarred = m.flags.includes("\\Flagged");
    await setStar(id, !isStarred);
    const btn = viewEl.querySelector('.reader-action[data-action="star"]');
    if (btn) {
        const now = !isStarred;
        btn.dataset.starred = now ? "1" : "0";
        btn.textContent = now ? "★" : "☆";
        btn.dataset.label = now ? "Unstar" : "Star";
        btn.title       = now ? "Unstar" : "Star";
    }
    await renderMessageList();
}

async function readerMarkUnread(id) {
    await setSeen(id, false);
    await renderMessageList();
    await loadFolders();
    toast("Marked unread.", "ok");
    document.getElementById("message-view")?.classList.remove("open");
    renderEmptyReader();
    state.selectedMessageId = null;
}

function printReader() {
    // The print stylesheet hides everything but the message body.
    window.print();
}

// Switch between rendered HTML and plain-text fallback for the same
// message. Useful when the HTML rendering is doing something weird
// (broken layout, dark-on-dark text from the sender's stylesheet, etc).
function toggleHtmlText(viewEl, parsed) {
    const bodyEl = viewEl.querySelector(".body-content");
    const btn    = viewEl.querySelector('[data-action="view-toggle"]');
    if (!bodyEl) return;
    if (state.readerView === "html") {
        bodyEl.classList.remove("html-body");
        bodyEl.classList.add("text-body");
        bodyEl.innerHTML = "";
        const pre = document.createElement("pre");
        pre.textContent = parsed.textBody || _htmlToText(parsed.htmlBody || "");
        bodyEl.appendChild(pre);
        state.readerView = "text";
        if (btn) {
            btn.textContent  = "❮❯";
            btn.dataset.label = "Rich HTML";
            btn.title         = "Switch back to HTML";
        }
    } else {
        bodyEl.classList.remove("text-body");
        bodyEl.classList.add("html-body");
        bodyEl.innerHTML = sanitiseHtml(parsed.htmlBody || "", {
            inlineImages: parsed.inlineImages,
            allowRemoteImages: false,
        });
        state.readerView = "html";
        if (btn) {
            btn.textContent  = "¶";
            btn.dataset.label = "Plain text";
            btn.title         = "Switch to plain text";
        }
    }
}

function toggleRawView(viewEl) {
    if (state.readerMode === "decoded") {
        // Replace pre body with raw RFC822 (escaped).
        const pre = viewEl.querySelector(".body-content");
        if (!pre) return;
        pre.dataset.decoded = pre.textContent;
        pre.textContent = state.readerRaw || "";
        state.readerMode = "raw";
        viewEl.classList.add("raw-mode");
    } else {
        const pre = viewEl.querySelector(".body-content");
        if (pre) pre.textContent = pre.dataset.decoded || "";
        state.readerMode = "decoded";
        viewEl.classList.remove("raw-mode");
    }
}

function _stripReplyPrefix(s) {
    return (s || "").replace(/^\s*(re|fwd?):\s*/gi, "").trim();
}
function _quotedBody(parsed) {
    const intro = parsed.from
        ? `\nOn ${parsed.date || "(unknown date)"}, ${parsed.from} wrote:\n`
        : "";
    const quoted = (parsed.body || "")
        .split(/\r?\n/)
        .map(l => "> " + l)
        .join("\n");
    return intro + quoted;
}

function openReplyCompose(parsed, replyAll) {
    openCompose();
    const form = $("#compose-form");
    const me = state.account?.email?.toLowerCase() || "";

    // To = original sender. Reply-all also fills Cc with the original
    // To and Cc minus our own address.
    form.elements.to.value = parsed.from || "";
    if (replyAll) {
        const others = [parsed.to, parsed.cc].filter(Boolean).join(", ");
        const filtered = others.split(/\s*,\s*/)
            .filter(Boolean)
            .filter(addr => !addr.toLowerCase().includes(me))
            .join(", ");
        if (filtered) {
            form.elements.cc.value = filtered;
            _showCcBcc(true);
        }
    }
    form.elements.subject.value = "Re: " + _stripReplyPrefix(parsed.subject);
    form.elements.body.value = "\n\n" + _quotedBody(parsed);
    form.dataset.inReplyTo = parsed.messageId || "";
    setTimeout(() => form.elements.body.focus(), 60);
}

function openForwardCompose(parsed) {
    openCompose();
    const form = $("#compose-form");
    form.elements.to.value = "";
    form.elements.subject.value = "Fwd: " + _stripReplyPrefix(parsed.subject);
    form.elements.body.value =
        `\n\n---------- Forwarded message ----------\n` +
        `From: ${parsed.from || ""}\n` +
        `Date: ${parsed.date || ""}\n` +
        `Subject: ${parsed.subject || ""}\n` +
        `To: ${parsed.to || ""}\n` +
        (parsed.cc ? `Cc: ${parsed.cc}\n` : "") +
        `\n${parsed.body || ""}\n`;
    delete form.dataset.inReplyTo;
    setTimeout(() => form.elements.to.focus(), 60);
}

async function deleteMessage(id) {
    await api.del(`/mail/messages/${id}`);
    toast("Message deleted.", "ok");
    try { await Search.forget(id); } catch {}
    state.messages = state.messages.filter(m => m.id !== id);
    state.selectedMessageId = null;
    renderEmptyReader();
    document.getElementById("message-view")?.classList.remove("open");
    await renderMessageList();
    await loadFolders();
}

async function markSpam(id, parsed) {
    // No move-to-spam endpoint yet; flag with \Junk and remove from
    // inbox via delete. The server keeps it as ciphertext only, so
    // marking-spam is essentially "discard with a flag attached".
    try {
        await api.post(`/mail/messages/${id}/flags`,
            { add: ["\\Junk"], remove: [] });
    } catch (e) { console.warn("[QloakMail] junk flag failed:", e); }
    await api.del(`/mail/messages/${id}`);
    toast("Marked as spam.", "ok");
    try { await Search.forget(id); } catch {}
    // Auto-add to blocklist if we know who sent it.
    if (parsed?.from) _addToBlocklist(_extractEmail(parsed.from));
    state.messages = state.messages.filter(m => m.id !== id);
    state.selectedMessageId = null;
    renderEmptyReader();
    document.getElementById("message-view")?.classList.remove("open");
    await renderMessageList();
    await loadFolders();
}

async function blockSender(parsed) {
    const addr = _extractEmail(parsed?.from || "");
    if (!addr) {
        toast("No sender address to block.", "err");
        return;
    }
    _addToBlocklist(addr);
    toast(`Blocked ${addr}. Future messages will be dropped client-side.`, "ok");
}

function _extractEmail(s) {
    if (!s) return "";
    const m = /<([^>]+)>/.exec(s);
    return (m ? m[1] : s).trim().toLowerCase();
}

function _blocklistKey() {
    return "qloakmail.blocklist." + (state.account?.account_id || "anon");
}
function _readBlocklist() {
    try { return JSON.parse(localStorage.getItem(_blocklistKey()) || "[]"); }
    catch { return []; }
}
function _addToBlocklist(addr) {
    if (!addr) return;
    const list = new Set(_readBlocklist());
    list.add(addr.toLowerCase());
    localStorage.setItem(_blocklistKey(), JSON.stringify([...list]));
}
function _removeFromBlocklist(addr) {
    const list = _readBlocklist().filter(a => a !== addr.toLowerCase());
    localStorage.setItem(_blocklistKey(), JSON.stringify(list));
}

function _showCcBcc(showCc) {
    $(".cc-row").hidden = !showCc;
    $(".bcc-row").hidden = !showCc;
    $("#cc-toggle").classList.toggle("active", showCc);
}

// ----------------------------------------------------------------- settings
function openSettings() {
    const p = loadPrefs();
    $("#settings-email").textContent = state.account?.email || "";
    $("#settings-onion").textContent = state.config?.onion_address || "—";
    Search.stats().then(s => {
        $("#settings-index-count").textContent = s.messages
            ? `${s.messages} messages` : "empty";
    }).catch(() => { $("#settings-index-count").textContent = "—"; });
    _renderBlocklist();

    // Reflect prefs back into the form controls.
    const sigEl = $("#settings-signature");
    if (sigEl) sigEl.value = p.signature || "";
    const densEl = $("#settings-density");
    if (densEl) densEl.value = p.density;
    const notifEl = $("#settings-notifications");
    if (notifEl) notifEl.checked = p.notifications;
    _renderAvatarPreview();

    $("#settings-modal").hidden = false;
}

function _renderAvatarPreview() {
    const preview = $("#settings-avatar-preview");
    const removeBtn = $("#settings-avatar-clear");
    const dp = (loadPrefs().avatar || "").trim();
    if (!preview) return;
    if (dp) {
        preview.classList.add("avatar-img");
        preview.style.background = "transparent";
        preview.innerHTML = `<img src="${escapeHtml(dp)}" alt="" />`;
        if (removeBtn) removeBtn.hidden = false;
    } else {
        preview.classList.remove("avatar-img");
        const { letter, color } = avatarFor(state.account?.email || "?");
        preview.style.background = color;
        preview.innerHTML = `<span class="avatar-letter">${escapeHtml(letter)}</span>`;
        if (removeBtn) removeBtn.hidden = true;
    }
}
function closeSettings() { $("#settings-modal").hidden = true; }

function _renderBlocklist() {
    const ul = $("#settings-blocklist");
    const list = _readBlocklist();
    if (!list.length) {
        ul.innerHTML = `<li class="empty"><em>No blocked senders.</em></li>`;
        return;
    }
    ul.innerHTML = list.map(addr =>
        `<li><span>${escapeHtml(addr)}</span>` +
        `<button class="unblock" data-addr="${escapeHtml(addr)}" type="button">Unblock</button></li>`
    ).join("");
    ul.querySelectorAll(".unblock").forEach(btn => {
        btn.addEventListener("click", () => {
            _removeFromBlocklist(btn.dataset.addr);
            _renderBlocklist();
        });
    });
}

function bindSettings() {
    $("#settings-btn")?.addEventListener("click", openSettings);
    $$("#settings-modal [data-close]").forEach(el =>
        el.addEventListener("click", closeSettings));
    $("#settings-clear-index")?.addEventListener("click", async () => {
        try { await Search.clear(); await Search.open(state.account.account_id); }
        catch (e) { console.warn("clear-index failed:", e); }
        $("#settings-index-count").textContent = "empty";
        toast("Local search index cleared.", "ok");
    });
    $("#settings-signout-all")?.addEventListener("click", () => {
        $("#logout-btn")?.click();
        closeSettings();
    });

    // Pref edits write back through savePrefs() so applyPrefsToDom
    // runs (e.g. density toggles a body class).
    const writeBack = (patch) => savePrefs({ ...loadPrefs(), ...patch });
    $("#settings-signature")?.addEventListener("change", e =>
        writeBack({ signature: e.target.value }));
    $("#settings-density")?.addEventListener("change", e =>
        writeBack({ density: e.target.value }));
    $("#settings-notifications")?.addEventListener("change", async (e) => {
        if (e.target.checked && "Notification" in window) {
            try {
                const perm = await Notification.requestPermission();
                if (perm !== "granted") {
                    e.target.checked = false;
                    toast("Notifications denied by browser.", "err");
                    return;
                }
            } catch { /* unsupported */ }
        }
        writeBack({ notifications: e.target.checked });
    });
    $("#settings-clear-drafts")?.addEventListener("click", () => {
        clearDraft();
        toast("Draft cleared.", "ok");
    });

    // Display-picture upload — file -> data URL into prefs.avatar.
    // Cap at ~256KB so we don't blow up localStorage; resize is left
    // to the user (kept simple — no canvas downscaling here).
    $("#settings-avatar-pick")?.addEventListener("click", () =>
        $("#settings-avatar-input")?.click());
    $("#settings-avatar-input")?.addEventListener("change", async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        if (file.size > 256 * 1024) {
            toast(`Image too large (${fmtBytes(file.size)}). Max 256 KB — try a smaller image.`, "err");
            e.target.value = "";
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            const dataUrl = String(reader.result);
            savePrefs({ ...loadPrefs(), avatar: dataUrl });
            _renderAvatarPreview();
            toast("Display picture saved.", "ok");
        };
        reader.onerror = () => toast("Could not read image.", "err");
        reader.readAsDataURL(file);
    });
    $("#settings-avatar-clear")?.addEventListener("click", () => {
        savePrefs({ ...loadPrefs(), avatar: "" });
        _renderAvatarPreview();
        toast("Display picture removed.", "ok");
    });
}

// ----------------------------------------------------------------- keyboard shortcuts
//
// Global key handler — only triggers when no modal is open and no
// editable input has focus. Mirrors the Gmail/Proton bindings users
// already know:
//   c = compose                   #/Delete = delete current message
//   r/a/f = reply/reply-all/fwd   ! = spam
//   e = toggle read/unread        s = star
//   /  = focus search             j/k = next/prev message
//   ?  = open shortcuts help (in settings)
//   Esc = handled elsewhere (close overlays)

function _isEditing(target) {
    if (!target) return false;
    const tag = target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    if (target.isContentEditable) return true;
    return false;
}
function _modalOpen() {
    return document.querySelector(".modal:not([hidden])") !== null;
}
function _readingMessage() {
    return state.selectedMessageId !== null && state.readerParsed !== null;
}

function bindShortcuts() {
    document.addEventListener("keydown", async (e) => {
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        if (_isEditing(e.target)) return;
        if (_modalOpen()) return;
        if (document.querySelector(".view.active")?.id !== "mail-view") return;

        const id = state.selectedMessageId;
        const parsed = state.readerParsed;

        switch (e.key) {
            case "c":
                e.preventDefault(); openCompose(); break;
            case "/":
                e.preventDefault(); $("#search-input")?.focus(); break;
            case "r":
                if (_readingMessage()) { e.preventDefault(); openReplyCompose(parsed, false); }
                break;
            case "a":
                if (_readingMessage()) { e.preventDefault(); openReplyCompose(parsed, true); }
                break;
            case "f":
                if (_readingMessage()) { e.preventDefault(); openForwardCompose(parsed); }
                break;
            case "e":
                if (_readingMessage()) { e.preventDefault(); await readerMarkUnread(id); }
                break;
            case "s":
                if (_readingMessage()) { e.preventDefault(); await toggleStar(id); }
                break;
            case "#":
            case "Delete":
                if (_readingMessage()) { e.preventDefault(); await deleteMessage(id); }
                break;
            case "!":
                if (_readingMessage()) { e.preventDefault(); await markSpam(id, parsed); }
                break;
            case "j":
            case "k":
                e.preventDefault(); _navigateList(e.key === "j" ? +1 : -1); break;
        }
    });
}

function _navigateList(delta) {
    const visible = applyListSortFilter(state.messages);
    if (!visible.length) return;
    const idx = state.selectedMessageId
        ? visible.findIndex(m => m.id === state.selectedMessageId)
        : -1;
    const next = (idx + delta + visible.length) % visible.length;
    openMessage(visible[(idx === -1 ? (delta > 0 ? 0 : visible.length - 1) : next)].id);
}

// ----------------------------------------------------------------- compose extras
//
// Cc/Bcc toggle, signature insertion, and draft auto-save. Drafts
// live in localStorage (DRAFT_KEY) so they survive accidental tab
// closes — the server has no draft endpoint yet, and we wouldn't
// want to send unencrypted drafts there anyway. Saved every 3s and
// on input throttle.

const DRAFT_KEY = "qloakmail.draft";
const DRAFT_INTERVAL_MS = 3000;
let _draftTimer = null;

function bindComposeExtras() {
    $("#cc-toggle")?.addEventListener("click", () => {
        const showing = !$(".cc-row").hidden;
        _showCcBcc(!showing);
    });

    const form = $("#compose-form");
    if (!form) return;

    // Auto-save every change (debounced 3s). Cleared when the message
    // is sent or the modal is closed via the cancel/× actions.
    form.addEventListener("input", () => {
        clearTimeout(_draftTimer);
        _draftTimer = setTimeout(saveDraft, DRAFT_INTERVAL_MS);
    });
}

function saveDraft() {
    const form = $("#compose-form");
    if (!form) return;
    const fd = new FormData(form);
    const draft = {
        to:      fd.get("to")      || "",
        cc:      fd.get("cc")      || "",
        bcc:     fd.get("bcc")     || "",
        subject: fd.get("subject") || "",
        body:    fd.get("body")    || "",
        inReplyTo: form.dataset.inReplyTo || "",
        savedAt: Date.now(),
    };
    // Don't save totally-empty drafts.
    if (!draft.to && !draft.subject && !draft.body) return;
    try { localStorage.setItem(DRAFT_KEY, JSON.stringify(draft)); }
    catch (e) { console.warn("[QloakMail] draft save failed:", e); }
}

function restoreDraft() {
    let d;
    try { d = JSON.parse(localStorage.getItem(DRAFT_KEY) || "null"); }
    catch { return false; }
    if (!d) return false;
    const form = $("#compose-form");
    if (!form) return false;
    form.elements.to.value      = d.to      || "";
    form.elements.cc.value      = d.cc      || "";
    form.elements.bcc.value     = d.bcc     || "";
    form.elements.subject.value = d.subject || "";
    form.elements.body.value    = d.body    || "";
    if (d.inReplyTo) form.dataset.inReplyTo = d.inReplyTo;
    if (d.cc || d.bcc) _showCcBcc(true);
    return true;
}

function clearDraft() {
    try { localStorage.removeItem(DRAFT_KEY); } catch {}
    clearTimeout(_draftTimer);
}

function appendSignature(form) {
    const sig = (loadPrefs().signature || "").trim();
    if (!sig) return;
    const ta = form.elements.body;
    if (!ta.value || !ta.value.includes(sig)) {
        ta.value = (ta.value || "") + (ta.value ? "\n\n" : "") + "-- \n" + sig;
    }
}

// ----------------------------------------------------------------- HTML sanitiser
//
// Strict allowlist sanitiser for inbound mail HTML. Defence against
// XSS embedded in the message body. Rules:
//   * Allowed tags only — block <script>, <iframe>, <object>, <embed>,
//     <form>, <input>, <link>, <meta>, <base>, <style> (style handled
//     specially below).
//   * Allowed attrs per tag. Strip every on* event handler. style
//     attributes are kept but property-filtered so url() / expression()
//     / position:fixed / behaviour: are out.
//   * href / src schemes whitelisted: http(s), mailto, cid:, data:
//     (data: only for img). javascript:/vbscript:/file: are out.
//   * Remote image src is rewritten to a placeholder until the user
//     clicks "Load images" (image-loading button toggles a class on
//     the body container that swaps placeholder -> original src).
//
// Notes:
//   * No DOMPurify dependency — keeps the bundle small and the
//     allowlist tight. Tradeoff: less battle-tested than DOMPurify;
//     consider swapping in for high-threat deployments.
//   * Inline cid:xxx images get rewritten in-place using the
//     inlineImages map produced by parseRfc822.

const HTML_ALLOWED_TAGS = new Set([
    "a","abbr","b","blockquote","br","caption","cite","code","col","colgroup",
    "dd","del","details","dfn","div","dl","dt","em","figcaption","figure",
    "h1","h2","h3","h4","h5","h6","hr","i","ins","kbd","li","mark","ol","p",
    "pre","q","s","samp","small","span","strong","sub","summary","sup",
    "table","tbody","td","tfoot","th","thead","time","tr","u","ul","wbr",
    "img"
]);
const HTML_ALLOWED_ATTRS = {
    a:    new Set(["href","title","name","rel","target"]),
    img:  new Set(["src","alt","title","width","height"]),
    "*":  new Set(["title","alt","class","colspan","rowspan","start","cite","datetime"]),
};
const URL_SAFE_SCHEMES_HREF = /^(https?:|mailto:|tel:|cid:|#)/i;
const URL_SAFE_SCHEMES_SRC  = /^(cid:|data:image\/)/i;       // remote http(s) is conditional
const URL_SAFE_SCHEMES_SRC_LOAD = /^(cid:|data:image\/|https?:)/i;

function sanitiseHtml(html, { inlineImages = new Map(), allowRemoteImages = false } = {}) {
    const doc = new DOMParser().parseFromString(html || "", "text/html");
    const root = doc.body;
    if (!root) return "";

    const SRC_RE = allowRemoteImages ? URL_SAFE_SCHEMES_SRC_LOAD : URL_SAFE_SCHEMES_SRC;

    const walk = (node) => {
        // Iterate a snapshot — we mutate during traversal.
        const children = [...node.children];
        for (const child of children) {
            const tag = child.tagName.toLowerCase();
            if (!HTML_ALLOWED_TAGS.has(tag)) {
                // Replace disallowed element with a div containing its
                // text content, so we don't drop user-readable text.
                const repl = doc.createElement("div");
                repl.textContent = child.textContent || "";
                child.replaceWith(repl);
                walk(repl);
                continue;
            }
            // Filter attributes.
            const allowed = HTML_ALLOWED_ATTRS[tag] || HTML_ALLOWED_ATTRS["*"];
            const allowedAlways = HTML_ALLOWED_ATTRS["*"];
            for (const attr of [...child.attributes]) {
                const n = attr.name.toLowerCase();
                if (n.startsWith("on")) { child.removeAttribute(n); continue; }
                if (n === "style") {
                    // Strip dangerous css. Drop `color:` entirely
                    // because senders almost always set it for a
                    // white shell — on our dark surface their
                    // dark-on-dark text becomes invisible. Keep
                    // background-color (CTAs / branded boxes) and
                    // structural properties (font, padding, etc).
                    const safe = (attr.value || "").split(";").map(s => s.trim()).filter(Boolean)
                        .filter(decl => /^(font(-[a-z]+)?|text(-[a-z]+)?|background-color|padding(-[a-z]+)?|margin(-[a-z]+)?|border(-[a-z]+)?|line-height|list-style(-[a-z]+)?|width|max-width|min-width|height|max-height|min-height|display|vertical-align|text-align|opacity|letter-spacing)\s*:/i.test(decl))
                        .filter(decl => !/url\s*\(|expression|behavior|@import|position\s*:\s*fixed/i.test(decl))
                        .join(";");
                    if (safe) child.setAttribute("style", safe);
                    else      child.removeAttribute("style");
                    continue;
                }
                if (!allowed.has(n) && !allowedAlways.has(n)) {
                    child.removeAttribute(n); continue;
                }
                if (tag === "a" && n === "href") {
                    if (!URL_SAFE_SCHEMES_HREF.test(attr.value)) {
                        child.removeAttribute(n);
                        continue;
                    }
                    // Force open-in-new-tab + no-referrer for external links.
                    if (/^https?:/i.test(attr.value)) {
                        child.setAttribute("target", "_blank");
                        child.setAttribute("rel", "noopener noreferrer");
                    }
                }
                if (tag === "img" && n === "src") {
                    // cid: -> data url substitution.
                    const cidMatch = /^cid:(.+)$/i.exec(attr.value);
                    if (cidMatch) {
                        const inline = inlineImages.get(cidMatch[1].trim());
                        if (inline) {
                            child.setAttribute("src", inline.dataUrl ||
                                `data:${inline.mime};base64,${inline.dataB64}`);
                        } else {
                            child.removeAttribute(n);
                        }
                        continue;
                    }
                    if (!SRC_RE.test(attr.value)) {
                        // Remote image while remote loading is off — stash original
                        // url + replace with a 1x1 blank so the layout doesn't break.
                        child.setAttribute("data-blocked-src", attr.value);
                        child.setAttribute("src", "data:image/gif;base64,R0lGODlhAQABAAAAACw=");
                        child.classList.add("blocked-image");
                    }
                }
            }
            walk(child);
        }
    };
    walk(root);
    return root.innerHTML;
}

function htmlBodyHasRemoteImages(html) {
    return /<img[^>]+src=["']https?:/i.test(html || "");
}

// ----------------------------------------------------------------- attachments
function downloadAttachment(att) {
    try {
        const bin = atob(att.dataB64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const blob = new Blob([bytes], { type: att.mime || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = att.filename || "attachment";
        document.body.appendChild(a);
        a.click();
        a.remove();
        // Revoke after the click so the browser has time to start the download.
        setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch (e) {
        console.error("[QloakMail] attachment download failed:", e);
        toast("Couldn't open attachment.", "err");
    }
}

function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function _attachmentIcon(mime) {
    if (!mime) return "▪";
    if (mime.startsWith("image/"))                  return "▦";
    if (mime.startsWith("video/"))                  return "▶";
    if (mime.startsWith("audio/"))                  return "♪";
    if (mime === "application/pdf")                 return "▤";
    if (/zip|rar|tar|gz|7z/.test(mime))             return "≡";
    if (/word|document|sheet|presentation/.test(mime)) return "▥";
    return "▪";
}

// ----------------------------------------------------------------- avatars
//
// Privacy-preserving avatar generator: deterministic colour from a
// hash of the email, plus the first letter of the local-part. No
// external services (Gravatar leaks the user's IP to Automattic).

function _hashStr(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 16777619);
    }
    return h >>> 0;
}
function avatarFor(addr) {
    if (!addr) return { letter: "?", color: "#444" };
    // Pull the local part out of "Name <user@domain>" or "user@domain".
    const m = /<([^>]+)>/.exec(addr);
    const email = (m ? m[1] : addr).trim();
    const local = email.split("@")[0] || email;
    const letter = (local[0] || "?").toUpperCase();
    const h = _hashStr(email.toLowerCase());
    // HSL palette tuned to the cyberpunk theme — warm hues only.
    const hue = (h % 60) + 8;          // 8–67° (red → orange → yellow)
    const sat = 55 + ((h >> 8) % 25);  // 55–80%
    const lig = 38 + ((h >> 16) % 12); // 38–50%
    return { letter, color: `hsl(${hue} ${sat}% ${lig}%)` };
}
function avatarHtml(addr, { size = 28, mine = false } = {}) {
    // If the user has set their own display picture and this is "us",
    // render that image instead of the generated initials.
    if (mine) {
        const dp = (loadPrefs().avatar || "").trim();
        if (dp) {
            return `<span class="avatar avatar-img" style="width:${size}px;height:${size}px;">` +
                   `<img src="${escapeHtml(dp)}" alt="" /></span>`;
        }
    }
    const { letter, color } = avatarFor(addr);
    return `<span class="avatar" style="width:${size}px;height:${size}px;background:${color};">` +
           `<span class="avatar-letter">${escapeHtml(letter)}</span></span>`;
}

function extractPgpPart(rfc822) {
    const m = rfc822.match(/-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/);
    if (!m) throw new Error("no PGP block found in message");
    return m[0];
}

function parseRfc822(raw) {
    // Returns the rich structured form. The legacy `body` field is
    // populated as the best-effort plaintext (for code that only
    // wants a string) but new callers should use textBody / htmlBody
    // / attachments / inlineImages.
    let eol = raw.indexOf("\r\n\r\n");
    let sepLen = 4;
    if (eol < 0) { eol = raw.indexOf("\n\n"); sepLen = 2; }

    const headerBlock = eol >= 0 ? raw.slice(0, eol) : raw;
    const rawBody     = eol >= 0 ? raw.slice(eol + sepLen) : "";
    const headers     = _parseHeaders(headerBlock);
    const ctype       = headers["content-type"] || "text/plain";
    const transferEnc = (headers["content-transfer-encoding"] || "7bit").toLowerCase();

    // Aggregate buckets the multipart walker fills into.
    const acc = {
        textBody: null,
        htmlBody: null,
        attachments: [],     // [{ filename, mime, size, dataB64 }]
        inlineImages: new Map(), // cid -> { mime, dataB64, dataUrl }
    };

    if (/^multipart\//i.test(ctype)) {
        _walkMultipart(rawBody, ctype, acc);
    } else if (/^text\/html/i.test(ctype)) {
        acc.htmlBody = _decodeTransfer(rawBody, transferEnc);
    } else if (/^text\//i.test(ctype) || ctype === "text/plain") {
        acc.textBody = _decodeTransfer(rawBody, transferEnc);
    } else {
        // Single-part non-text body — treat as a download attachment.
        const fnameMatch = /name=("([^"]+)"|([^;\s]+))/i.exec(ctype) ||
                           /filename=("([^"]+)"|([^;\s]+))/i.exec(headers["content-disposition"] || "");
        acc.attachments.push({
            filename: fnameMatch ? (fnameMatch[2] || fnameMatch[3]) : "attachment",
            mime: ctype.split(";")[0].trim(),
            size: rawBody.length,
            dataB64: transferEnc === "base64" ? rawBody.replace(/\s+/g, "") : btoa(rawBody),
        });
    }

    // Resolve cid: -> data URL for inline images.
    for (const [cid, img] of acc.inlineImages) {
        img.dataUrl = `data:${img.mime};base64,${img.dataB64}`;
    }

    // Legacy plaintext body: prefer text part; else strip HTML.
    const legacyBody = acc.textBody
        ? acc.textBody
        : acc.htmlBody
            ? _htmlToText(acc.htmlBody)
            : rawBody;

    return {
        from:    headers.from       || "",
        to:      headers.to         || "",
        cc:      headers.cc         || "",
        subject: headers.subject    || "",
        date:    headers.date       || "",
        messageId:  headers["message-id"] || "",
        references: headers.references   || headers["in-reply-to"] || "",
        textBody:    acc.textBody,
        htmlBody:    acc.htmlBody,
        attachments: acc.attachments,
        inlineImages: acc.inlineImages,
        body: legacyBody,
    };
}

function _parseHeaders(block) {
    const headers = {};
    let cur = "";
    for (const line of block.split(/\r?\n/)) {
        if (/^[ \t]/.test(line) && cur) {
            // RFC 5322 header continuation.
            headers[cur] += " " + line.trim();
        } else {
            const i = line.indexOf(":");
            if (i > 0) {
                cur = line.slice(0, i).toLowerCase();
                headers[cur] = line.slice(i + 1).trim();
            }
        }
    }
    // RFC 2047 decode for human-readable header values (Subject,
    // From, To, Cc). =?charset?B?...?= or =?charset?Q?...?= replaced
    // with the decoded UTF-8 string. Bare ASCII passes through.
    for (const k of ["subject", "from", "to", "cc"]) {
        if (headers[k]) headers[k] = _decodeMimeWords(headers[k]);
    }
    return headers;
}

function _decodeMimeWords(s) {
    return s.replace(
        /=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s*)(?==\?|\s|$)/g,
        (_, charset, enc, payload) => {
            try {
                let bytes;
                if (enc.toUpperCase() === "B") {
                    const bin = atob(payload.replace(/\s+/g, ""));
                    bytes = new Uint8Array(bin.length);
                    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
                } else {
                    // Q-encoding: like quoted-printable but `_` means space.
                    const qp = payload.replace(/_/g, " ");
                    const buf = [];
                    for (let i = 0; i < qp.length; i++) {
                        if (qp[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(qp.substr(i + 1, 2))) {
                            buf.push(parseInt(qp.substr(i + 1, 2), 16));
                            i += 2;
                        } else {
                            buf.push(qp.charCodeAt(i) & 0xff);
                        }
                    }
                    bytes = new Uint8Array(buf);
                }
                return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
            } catch { return _; }
        }
    );
}

// Walks a multipart/* body, recursively, populating the accumulator
// with text/html bodies, attachments, and inline images. The same
// function handles multipart/alternative (text/plain + text/html),
// multipart/related (HTML + cid: inline images), multipart/mixed
// (mail body + attachments), and any nesting of the three.
function _walkMultipart(rawBody, ctypeHeader, acc) {
    const m = /boundary=("([^"]+)"|([^;\s]+))/i.exec(ctypeHeader);
    if (!m) return;
    const boundary = m[2] || m[3];
    const parts = rawBody.split(
        new RegExp(`--${boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:--)?`)
    );

    for (const p of parts) {
        if (!p.trim()) continue;
        const sepMatch = /\r\n\r\n|\n\n/.exec(p);
        if (!sepMatch) continue;

        const partHeaderBlock = p.slice(0, sepMatch.index);
        const partBodyRaw     = p.slice(sepMatch.index + sepMatch[0].length).replace(/\r?\n*$/, "");
        const ph              = _parseHeaders(partHeaderBlock);
        const partCtype       = ph["content-type"]              || "";
        const partEnc         = (ph["content-transfer-encoding"] || "7bit").toLowerCase();
        const partDisp        = ph["content-disposition"]       || "";
        const cidRaw          = ph["content-id"]                || "";
        const cid             = cidRaw.replace(/^<|>$/g, "").trim();

        if (/^multipart\//i.test(partCtype)) {
            _walkMultipart(partBodyRaw, partCtype, acc);
            continue;
        }

        const isAttach = /^attachment/i.test(partDisp);
        const isInline = /^inline/i.test(partDisp) || cid;
        const dispFnameMatch = /filename=("([^"]+)"|([^;\s]+))/i.exec(partDisp) ||
                               /name=("([^"]+)"|([^;\s]+))/i.exec(partCtype);
        const filename = dispFnameMatch ? (dispFnameMatch[2] || dispFnameMatch[3]) : null;
        const mime = partCtype.split(";")[0].trim().toLowerCase();

        if (/^text\/plain/i.test(partCtype) && !isAttach) {
            if (acc.textBody === null) acc.textBody = _decodeTransfer(partBodyRaw, partEnc);
        } else if (/^text\/html/i.test(partCtype) && !isAttach) {
            if (acc.htmlBody === null) acc.htmlBody = _decodeTransfer(partBodyRaw, partEnc);
        } else if (/^image\//i.test(partCtype) && (isInline || cid)) {
            // Inline image — store base64 with its CID for HTML resolution.
            const dataB64 = partEnc === "base64"
                ? partBodyRaw.replace(/\s+/g, "")
                : btoa(_decodeTransfer(partBodyRaw, partEnc));
            if (cid) acc.inlineImages.set(cid, { mime, dataB64 });
            // Inline images that aren't referenced are also useful as
            // download-able attachments.
            acc.attachments.push({
                filename: filename || `image-${acc.attachments.length + 1}`,
                mime, size: dataB64.length,
                dataB64, inline: true, cid: cid || null,
            });
        } else {
            // Anything else (PDFs, docs, archives, octet-stream): attachment.
            const dataB64 = partEnc === "base64"
                ? partBodyRaw.replace(/\s+/g, "")
                : btoa(_decodeTransfer(partBodyRaw, partEnc));
            acc.attachments.push({
                filename: filename || "attachment",
                mime, size: dataB64.length,
                dataB64,
            });
        }
    }
}

// Transfer-encoding decode that produces a UTF-8 string. base64 and
// quoted-printable both encode arbitrary BYTES, not characters; a
// UTF-8 character may span 2-4 of those bytes. We must reassemble
// the byte sequence then decode as UTF-8, otherwise multi-byte
// codepoints (â / ' / é / non-ASCII anything) show up as mojibake
// like "donâ€™t".
function _decodeTransfer(body, enc) {
    const utf8 = new TextDecoder("utf-8", { fatal: false });
    if (enc === "base64") {
        try {
            const bin = atob(body.replace(/\s+/g, ""));
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
            return utf8.decode(bytes);
        } catch { return body; }
    }
    if (enc === "quoted-printable") {
        // Strip soft line breaks, then walk the string assembling a
        // byte buffer. Each =XX is one byte; everything else is its
        // own char (assumed ASCII -> 1 byte).
        const noSoftBreaks = body.replace(/=\r?\n/g, "");
        const bytes = [];
        for (let i = 0; i < noSoftBreaks.length; i++) {
            const c = noSoftBreaks[i];
            if (c === "=" && i + 2 < noSoftBreaks.length) {
                const hex = noSoftBreaks.substr(i + 1, 2);
                if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
                    bytes.push(parseInt(hex, 16));
                    i += 2;
                    continue;
                }
            }
            bytes.push(c.charCodeAt(0) & 0xff);
        }
        return utf8.decode(new Uint8Array(bytes));
    }
    return body;
}

// Tag stripper for text/html parts. Not a sanitiser — the result is
// rendered as plaintext via .textContent on a <pre>, so any residual
// markup will display as text, not be parsed.
function _htmlToText(html) {
    return html
        .replace(/<style[\s\S]*?<\/style>/gi, "")
        .replace(/<script[\s\S]*?<\/script>/gi, "")
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/(p|div|h[1-6]|li|tr|blockquote)>/gi, "\n")
        .replace(/<[^>]+>/g, "")
        .replace(/&nbsp;/g, " ")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#0?39;/g, "'")
        .replace(/&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
        .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

// ----------------------------------------------------------------- search
function bindSearch() {
    const input = $("#search-input");
    input.addEventListener("input", (e) => {
        clearTimeout(state.searchTimer);
        const q = e.target.value.trim();
        state.searchTimer = setTimeout(() => runSearch(q), 180);
    });
    input.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            input.value = "";
            runSearch("");
            input.blur();
        }
    });
}

async function runSearch(query) {
    if (!query) {
        state.searchActive = false;
        renderMessageList();
        await refreshSearchStats();
        return;
    }
    state.searchActive = true;

    let results = [];
    try {
        results = await Search.search(query);
    } catch (e) {
        console.error("[QloakMail] search failed:", e);
    }

    const ul = $("#message-list");
    ul.innerHTML = "";
    $("#search-stats").textContent = results.length
        ? `${results.length} match${results.length === 1 ? "" : "es"}`
        : "no matches";

    if (!results.length) {
        ul.innerHTML = `
            <li class="empty-state">
                <h4>No matches</h4>
                <p>Search runs only on messages you've already opened in this browser.</p>
            </li>
        `;
        return;
    }

    for (const r of results) {
        const li = document.createElement("li");
        li.className = "search-result";
        if (r.id === state.selectedMessageId) li.classList.add("active");
        const when = r.date ? fmtRelative(r.date) : "";
        li.innerHTML = `
            <span class="when">${escapeHtml(when)}</span>
            <div class="from">${escapeHtml(r.from || "(unknown)")}</div>
            <div class="subject">${escapeHtml(r.subject || "(no subject)")}</div>
            <div class="snippet">${escapeHtml(r.snippet || "")}</div>
        `;
        li.addEventListener("click", () => openMessage(r.id));
        ul.appendChild(li);
    }
}

// ----------------------------------------------------------------- compose
function openCompose() {
    $("#compose-modal").hidden = false;
    const form = $("#compose-form");
    // Restore draft if there is one and we're not pre-filling from a
    // reply (data-in-reply-to set means the caller already populated).
    if (!form.dataset.inReplyTo && !form.elements.to.value) {
        if (restoreDraft()) toast("Restored draft.", "");
        else                appendSignature(form);
    }
    setTimeout(() => form.elements.to.focus(), 50);
}
function closeCompose() {
    $("#compose-modal").hidden = true;
    setStatus($("#compose-status"), "");
    // We KEEP the draft on close — it's restored next time. Only the
    // submit handler clears it on a successful send.
}

function bindCompose() {
    $("#compose-btn").addEventListener("click", openCompose);

    // Backdrop, X button, and any [data-close] element close the modal.
    $$("#compose-modal [data-close]").forEach(el => {
        el.addEventListener("click", closeCompose);
    });

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && !$("#compose-modal").hidden) {
            closeCompose();
        }
    });

    $("#compose-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const status = $("#compose-status");
        const fd = new FormData(e.target);
        const splitAddrs = (s) => (s || "").split(",").map(x => x.trim()).filter(Boolean);
        const to  = splitAddrs(fd.get("to"));
        const cc  = splitAddrs(fd.get("cc"));
        const bcc = splitAddrs(fd.get("bcc"));
        const subject = fd.get("subject") || "";
        const body = fd.get("body") || "";
        const inReplyTo = e.target.dataset.inReplyTo || "";

        setStatus(status, "Sending...");
        try {
            const internalDomains = new Set((state.config?.domains || []).map(d => d.toLowerCase()));
            const isInternal = (addr) => internalDomains.has(addr.split("@")[1]?.toLowerCase());

            // Header order matters less than completeness — assemble
            // To, Cc (visible), and skip Bcc on the wire (the whole
            // point). Bcc recipients still go in the rcpt_to list so
            // SMTP delivers them; they just never appear in headers.
            const headerLines = [
                `From: ${state.account.email}`,
                `To: ${to.join(", ")}`,
            ];
            if (cc.length)  headerLines.push(`Cc: ${cc.join(", ")}`);
            headerLines.push(`Subject: ${subject}`);
            headerLines.push(`Date: ${new Date().toUTCString()}`);
            headerLines.push(`Message-ID: <${crypto.randomUUID()}@${state.account.email.split("@")[1]}>`);
            if (inReplyTo) {
                headerLines.push(`In-Reply-To: ${inReplyTo}`);
                headerLines.push(`References: ${inReplyTo}`);
            }
            headerLines.push(`MIME-Version: 1.0`);
            headerLines.push(`Content-Type: text/plain; charset=utf-8`);
            const headers = headerLines.join("\r\n");
            const rfc822 = headers + "\r\n\r\n" + body;

            const allRcpt = [...to, ...cc, ...bcc];
            await api.post("/mail/send", {
                rfc822_b64: b64encode(new TextEncoder().encode(rfc822)),
                rcpt_to: allRcpt,
                is_internal_only: allRcpt.every(isInternal),
            });
            setStatus(status, "Sent.", "ok");
            toast("Message sent", "ok");
            clearDraft();
            setTimeout(() => {
                closeCompose();
                e.target.reset();
                _showCcBcc(false);              // collapse Cc/Bcc rows
                delete e.target.dataset.inReplyTo;
            }, 600);
        } catch (err) {
            console.error(err);
            setStatus(status, "Send failed: " + (err.message || err), "err");
        }
    });
}

// ----------------------------------------------------------------- matrix rain
//
// Subtle Japanese-character rain behind the auth and unlock views.
// Dark gray with a faint warm tint so it reads as ambient texture
// rather than primary content. Pauses when the canvas isn't visible
// (mail-view has no .matrix-on class on body) — the requestAnimationFrame
// loop continues but the draw call early-returns.
//
// Skipped entirely under prefers-reduced-motion (handled in CSS via
// display:none + here via initMatrix() short-circuit).

const MATRIX_GLYPHS =
    // Katakana
    "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン" +
    // Hiragana (sparser)
    "あいうえおかきくけこさしすせそ" +
    // Half-width tech symbols
    "0123456789!?+-*/=<>{}[]#$%&@";

function initMatrix() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const canvas = document.getElementById("matrix-bg");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const FONT_SIZE = 14;
    let cols = 0;
    let drops = [];
    let dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));

    function resize() {
        const w = window.innerWidth;
        const h = window.innerHeight;
        canvas.width  = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        canvas.style.width  = w + "px";
        canvas.style.height = h + "px";
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        cols = Math.ceil(w / FONT_SIZE);
        // Stagger initial drop positions so the rain doesn't start as
        // a uniform wall.
        drops = new Array(cols).fill(0).map(() => Math.random() * -50);
    }
    resize();
    window.addEventListener("resize", resize);

    let frame = 0;
    function draw() {
        // Only render while the matrix-on class is on body. Saves CPU
        // on the mail-view.
        if (!document.body.classList.contains("matrix-on")) {
            requestAnimationFrame(draw);
            return;
        }
        // Step every third frame — slows the rain to ~20fps and reduces
        // GPU pressure while keeping motion smooth.
        frame++;
        if (frame % 3) {
            requestAnimationFrame(draw);
            return;
        }

        const w = window.innerWidth;
        const h = window.innerHeight;

        // Translucent dark wash → leaves fading trails of past chars.
        // Lower alpha = trails persist longer for a more visible rain.
        ctx.fillStyle = "rgba(5, 8, 7, 0.07)";
        ctx.fillRect(0, 0, w, h);

        ctx.font = `${FONT_SIZE}px ui-monospace, "SF Mono", Menlo, Consolas, monospace`;
        ctx.textBaseline = "top";

        for (let i = 0; i < cols; i++) {
            const ch = MATRIX_GLYPHS[
                (Math.random() * MATRIX_GLYPHS.length) | 0
            ];
            const x = i * FONT_SIZE;
            const y = drops[i] * FONT_SIZE;

            // Warm orange tint to match the deep-orange theme. The head
            // of each stream gets a brighter saturated orange; the trail
            // is a dimmer burnt-orange.
            const isHead = Math.random() < 0.04;
            ctx.fillStyle = isHead
                ? "rgba(255, 138, 61, 0.85)"
                : "rgba(140, 70, 25, 0.75)";
            ctx.fillText(ch, x, y);

            // Reset to top with random delay; longer streams look
            // organic.
            if (y > h && Math.random() > 0.985) drops[i] = 0;
            drops[i] += 0.55;
        }

        requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
}

// ----------------------------------------------------------------- live log strip
//
// Types one of FEATURES_LOG_LINES into #features-log-line, pauses, then
// deletes and types the next — the "always being written" effect for
// the [STATUS] panel. Pure cosmetic; copy is rotated through a small
// pool of plausible-sounding diagnostics so it doesn't loop too fast.
//
// Skipped under prefers-reduced-motion; quietly no-ops if the element
// isn't in the current view (recovery view + mail view don't render it).

// Each line is rendered as a three-part flex row in the status box:
// [key] [dotted leader that flex-grows to fill] [result tag].
// The CSS dotted-border on .status-dots stretches to whatever width
// is left, so the dots always reach the result tag regardless of the
// box width.
const FEATURES_LOG_LINES = [
    { key: "scan:   probing all checks",     result: "[PASS]" },
    { key: "verify: key wrap integrity",     result: "[OK]" },
    { key: "audit:  ciphertext mailstore",   result: "[OK]" },
    { key: "ping:   session token rotation", result: "[OK]" },
    { key: "trace:  zero log retention",     result: "[CONFIRMED]" },
    { key: "probe:  auth verifier",          result: "[PASS]" },
    { key: "watch:  hidden service reach",   result: "[UP]" },
    { key: "audit:  client integrity",       result: "[MATCH]" },
    { key: "ping:   privacy edge node",      result: "[83ms]" },
    { key: "scan:   outbound rate-limit",    result: "[ARMED]" },
];

function startFeaturesLogLoop() {
    // Compact version (was the typewriter strip) — no longer in the
    // markup, but kept as a no-op so the boot() call site doesn't break
    // when we drop the panel back in on the about page.
    const el = document.getElementById("features-log-line");
    if (!el) return;
    const asLine = ({ key, result }) => `${key} ........ ${result}`;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        el.textContent = asLine(FEATURES_LOG_LINES[0]);
        return;
    }

    let idx = 0;
    let stopped = false;

    async function typewrite(text, speed) {
        for (let i = 0; i < text.length && !stopped; i++) {
            el.textContent = text.slice(0, i + 1);
            await new Promise(r => setTimeout(r, speed + (Math.random() * 14 - 7)));
        }
    }
    async function backspace(speed) {
        let t = el.textContent;
        while (t.length > 0 && !stopped) {
            t = t.slice(0, -1);
            el.textContent = t;
            await new Promise(r => setTimeout(r, speed));
        }
    }

    (async function loop() {
        while (!stopped) {
            const line = asLine(FEATURES_LOG_LINES[idx % FEATURES_LOG_LINES.length]);
            await typewrite(line, 22);
            await new Promise(r => setTimeout(r, 1900));
            await backspace(8);
            await new Promise(r => setTimeout(r, 200));
            idx++;
        }
    })();
}

// Populates the vertical terminal-feed box at the bottom of the auth
// card. Each entry becomes a three-part <li class="status-line">:
//   <span class="status-key">…label…</span>
//   <span class="status-dots"></span>      <- flex-grow dotted leader
//   <span class="status-result">[TAG]</span>
// The CSS dotted-border on .status-dots stretches to fill whatever
// width is left so the dots always reach the result tag. The two
// .status-track-half lists hold identical content so the CSS
// animation (translateY 0 -> -50%) loops seamlessly upward.
function bindStatusScroller() {
    const halves = document.querySelectorAll(".status-scroller .status-track-half");
    if (!halves.length) return;
    const tagClass = (tag) => {
        if (tag === "[PASS]") return "pass";
        if (/^\[\d+ms\]$/.test(tag)) return "num";
        return "ok";
    };
    const escape = s => s
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const itemsHtml = FEATURES_LOG_LINES
        .map(({ key, result }) => `<li class="status-line">` +
            `<span class="status-key">${escape(key)}</span>` +
            `<span class="status-dots" aria-hidden="true"></span>` +
            `<span class="status-result ${tagClass(result)}">${escape(result)}</span>` +
            `</li>`)
        .join("");
    halves.forEach(el => { el.innerHTML = itemsHtml; });
}

// ----------------------------------------------------------------- ripple effect
//
// Material-style click ripple on every primary button (and re-applies to
// any .primary added after boot). Pure visual; pointer-events:none on
// the spawned span keeps it from interfering with the actual click.
function bindRipples() {
    document.body.addEventListener("click", (e) => {
        const btn = e.target.closest(".primary, .compose-btn");
        if (!btn || btn.disabled) return;
        const rect = btn.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const ripple = document.createElement("span");
        ripple.className = "ripple";
        ripple.style.left = x + "px";
        ripple.style.top = y + "px";
        // Width matches the longest dimension of the button so the
        // ripple covers it fully when scaled.
        const size = Math.max(rect.width, rect.height) * 0.04;
        ripple.style.width = size + "px";
        ripple.style.height = size + "px";
        btn.appendChild(ripple);
        setTimeout(() => ripple.remove(), 600);
    }, { capture: false });
}

// ----------------------------------------------------------------- idle auto-lock
//
// After IDLE_TIMEOUT_MS of no user activity in the mail view, drop the
// in-memory plaintext private key and bounce the user to the unlock
// view. This limits the post-compromise window — if someone walks away
// from a logged-in session and someone else picks up the device, they
// hit a password prompt rather than an open inbox.
//
// "Activity" is any pointer/keyboard/scroll event. We also pause the
// timer when the tab is hidden so a backgrounded tab isn't constantly
// "active" because of focus events firing in the background.
//
// 15 minutes balances "long enough to switch tabs and read a doc" vs
// "short enough that a stolen unlocked laptop doesn't expose mail
// indefinitely". Hardcoded — could be a per-user pref later.

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
let _idleTimer = null;
let _idleArmed = false;

function armIdleLock() {
    if (_idleArmed) return;
    _idleArmed = true;
    const reset = () => {
        clearTimeout(_idleTimer);
        if (document.hidden) return;          // don't tick while hidden
        _idleTimer = setTimeout(triggerIdleLock, IDLE_TIMEOUT_MS);
    };
    ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(ev =>
        document.addEventListener(ev, reset, { passive: true }));
    document.addEventListener("visibilitychange", reset);
    reset();
}

function disarmIdleLock() {
    _idleArmed = false;
    clearTimeout(_idleTimer);
    _idleTimer = null;
}

function triggerIdleLock() {
    // Only meaningful while the user is in the mailbox with a live key.
    if (!state.privkey) return;
    if (document.querySelector(".view.active")?.id !== "mail-view") return;

    // Drop the plaintext key and any decrypted state. Keep the encrypted
    // session blob intact so unlockSession() can re-derive after the
    // user re-enters their password.
    state.privkey = null;
    state.pubkey = null;
    state.messages = [];
    state.selectedMessageId = null;
    api.setToken(null);

    // If the stored session has the encrypted blob, send the user to
    // unlock; otherwise to a fresh sign-in.
    const sess = loadSession();
    if (sess && sess.encrypted_privkey_password) {
        // Strip any cached plaintext key (from a remember-me window)
        // so unlock has to re-derive from the password.
        const { privkey_armored, expires_at, ...minimal } = sess;
        const target = localStorage.getItem(SESSION_KEY) ? localStorage : sessionStorage;
        target.setItem(SESSION_KEY, JSON.stringify(minimal));
        $("#unlock-email").textContent = sess.email;
        show("unlock-view");
        toast("Locked due to inactivity — sign back in.", "");
        setTimeout(() => $("#unlock-form input[name=password]").focus(), 50);
    } else {
        clearSession();
        show("auth-view");
        toast("Locked due to inactivity.", "");
    }
    disarmIdleLock();
}

// ----------------------------------------------------------------- clipboard auto-clear
//
// When the user copies sensitive material (recovery code, onion
// address) we schedule a write of an empty string to the clipboard
// AUTO_CLEAR_MS later. Defends against the "open recovery code, copy,
// paste, walk away with it still in clipboard" mistake.
//
// Best-effort: if the user has copied something else in the meantime
// we'll still overwrite that. Tradeoff: better to lose a clipboard
// than leak a recovery code. Skip if Clipboard API not available.

const CLIPBOARD_AUTO_CLEAR_MS = 30 * 1000;

function scheduleClipboardClear() {
    if (!navigator.clipboard?.writeText) return;
    setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => { /* user navigated away — fine */ });
    }, CLIPBOARD_AUTO_CLEAR_MS);
}

// ----------------------------------------------------------------- admin panel
//
// Loaded only when /users/me returns is_admin: true. Surfaces the
// admin gear in the settings modal and a tabbed control panel
// (stats / accounts / ip-bans). Every call hits /api/v1/admin/*,
// which is gated by current_admin on the server — non-admins get
// 404 from the API. We mirror the same UX in the SPA: the entry
// button stays hidden unless the server confirms admin status, so
// the panel doesn't even hint at its existence to regular users.

const ADMIN_PAGE_SIZE = 25;
let _adminAccountState = { offset: 0, total: 0, q: "" };

async function refreshAdminGate() {
    try {
        const me = await api.get("/users/me");
        const sec = $("#settings-admin-section");
        if (sec) sec.hidden = !me.is_admin;
        state.isAdmin = !!me.is_admin;
    } catch { state.isAdmin = false; }
}

function bindAdmin() {
    $("#settings-open-admin")?.addEventListener("click", () => {
        closeSettings();
        openAdmin();
    });
    $$("#admin-modal [data-close]").forEach(el =>
        el.addEventListener("click", () => $("#admin-modal").hidden = true));
    $$("#admin-modal .admin-tab").forEach(tab => {
        tab.addEventListener("click", () => switchAdminTab(tab.dataset.adminTab));
    });
    $("#admin-refresh")?.addEventListener("click", () => loadAdminStats());

    // Accounts tab
    let _searchTimer = null;
    $("#admin-account-search")?.addEventListener("input", (e) => {
        clearTimeout(_searchTimer);
        _searchTimer = setTimeout(() => {
            _adminAccountState.q = e.target.value.trim();
            _adminAccountState.offset = 0;
            loadAdminAccounts();
        }, 220);
    });
    $("#admin-prev")?.addEventListener("click", () => {
        _adminAccountState.offset = Math.max(0, _adminAccountState.offset - ADMIN_PAGE_SIZE);
        loadAdminAccounts();
    });
    $("#admin-next")?.addEventListener("click", () => {
        if (_adminAccountState.offset + ADMIN_PAGE_SIZE < _adminAccountState.total) {
            _adminAccountState.offset += ADMIN_PAGE_SIZE;
            loadAdminAccounts();
        }
    });

    // IP bans tab
    $("#admin-ipban-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const fd = new FormData(e.target);
        const body = {
            ip: fd.get("ip"),
            reason: fd.get("reason") || null,
            ttl_hours: fd.get("ttl_hours") ? +fd.get("ttl_hours") : null,
        };
        try {
            await api.post("/admin/ip-blocks", body);
            e.target.reset();
            await loadAdminIpBans();
            _adminToast("IP ban added.", "ok");
        } catch (err) {
            _adminToast("Failed: " + (err.message || err), "err");
        }
    });
}

function openAdmin() {
    if (!state.isAdmin) return;
    $("#admin-modal").hidden = false;
    switchAdminTab("stats");
}

function switchAdminTab(name) {
    $$("#admin-modal .admin-tab").forEach(t =>
        t.classList.toggle("active", t.dataset.adminTab === name));
    $$("#admin-modal .admin-pane").forEach(p =>
        p.hidden = p.dataset.pane !== name);
    if (name === "stats")     loadAdminStats();
    if (name === "accounts")  loadAdminAccounts();
    if (name === "ip-bans")   loadAdminIpBans();
    if (name === "audit-log") loadAdminAuditLog();
}

function _adminToast(msg, kind) {
    const el = $("#admin-status");
    if (!el) return;
    el.textContent = msg;
    el.className = "status" + (kind ? " " + kind : "");
    setTimeout(() => { el.textContent = ""; el.className = "status"; }, 3500);
}

function _fmtBytes(n) { return fmtBytes(n); }
function _fmtDate(s) {
    if (!s) return "—";
    const d = new Date(s);
    return isNaN(d) ? s : d.toLocaleString();
}

async function loadAdminStats() {
    try {
        const [s, visitors, sigs, loginOk, loginFail, msgs, rl, storage] = await Promise.all([
            api.get("/admin/stats"),
            api.get("/admin/timeseries/visitors?days=30"),
            api.get("/admin/timeseries/signups?days=30"),
            api.get("/admin/timeseries/login-ok?days=30"),
            api.get("/admin/timeseries/login-fail?days=30"),
            api.get("/admin/timeseries/messages?days=30"),
            api.get("/admin/timeseries/rate-limit?days=30"),
            api.get("/admin/top-storage?limit=10"),
        ]);
        // Existing tiles.
        $("#stat-accounts-total").textContent = s.accounts_total;
        $("#stat-accounts-breakdown").textContent =
            `${s.accounts_active} active · ${s.accounts_banned} banned · ${s.accounts_pending} pending`;
        $("#stat-signups-24h").textContent = s.signups_24h;
        $("#stat-signups-7d").textContent  = s.signups_7d;
        $("#stat-signups-30d").textContent = s.signups_30d;
        $("#stat-messages-total").textContent = s.messages_total;
        $("#stat-messages-24h").textContent   = s.messages_24h;
        $("#stat-storage").textContent  = _fmtBytes(s.storage_bytes_used);
        $("#stat-ip-bans").textContent  = s.ip_blocks_active;
        // New aggregate-counter tiles (zero-init if backend hasn't been
        // upgraded yet, so older deploys don't blow up).
        $("#stat-boot-24h").textContent       = s.boot_pings_24h ?? 0;
        $("#stat-boot-7d").textContent        = s.boot_pings_7d ?? 0;
        $("#stat-active-sessions").textContent= s.active_sessions ?? 0;
        $("#stat-login-ok-24h").textContent   = s.login_ok_24h ?? 0;
        $("#stat-login-fail-24h").textContent = s.login_fail_24h ?? 0;
        $("#stat-rl-24h").textContent         = s.rate_limit_hits_24h ?? 0;
        $("#stat-msgrx-24h").textContent      = s.msg_rx_24h ?? 0;
        $("#stat-msgrx-7d").textContent       = s.msg_rx_7d ?? 0;

        renderTimeChart($("#chart-visitors"),   visitors);
        renderTimeChart($("#chart-signups"),    sigs);
        renderStackedLoginChart($("#chart-logins"), loginOk, loginFail);
        renderTimeChart($("#chart-messages"),   msgs);
        renderTimeChart($("#chart-rate-limit"), rl);
        renderTopStorage($("#admin-top-storage"), storage, s.storage_bytes_used);
    } catch (e) {
        _adminToast("Stats load failed: " + (e.message || e), "err");
    }
}

// Two-series stacked chart for login outcomes. Same skeleton as
// renderTimeChart but draws the failure series in red ON TOP of the
// success series in orange so an admin can spot brute-force days
// (red dominates) at a glance.
function renderStackedLoginChart(host, okPoints, failPoints) {
    if (!host) return;
    const len = Math.max(okPoints.length, failPoints.length);
    if (!len) { host.innerHTML = ""; return; }
    const merged = [];
    for (let i = 0; i < len; i++) {
        const o = okPoints[i]?.count || 0;
        const f = failPoints[i]?.count || 0;
        merged.push({ date: okPoints[i]?.date || failPoints[i]?.date, count: o + f, _ok: o, _fail: f });
    }
    const w = host.clientWidth || 320;
    const h = 200;
    const pad = { l: 36, r: 14, t: 16, b: 28 };
    const innerW = w - pad.l - pad.r;
    const innerH = h - pad.t - pad.b;
    const max = Math.max(1, ...merged.map(p => p.count));
    const stepX = merged.length > 1 ? innerW / (merged.length - 1) : 0;
    const yOf = v => pad.t + innerH - (v / max) * innerH;

    const bars = merged.map((p, i) => {
        const bw = Math.max(1, stepX * 0.55);
        const x  = pad.l + i * stepX - bw / 2;
        const yTop  = yOf(p.count);
        const yFail = yOf(p._fail);
        const okH   = pad.t + innerH - yFail;
        const failH = yFail - yTop;
        return `<rect x="${x}" y="${yFail}" width="${bw}" height="${okH}" fill="rgba(255,138,61,0.55)"></rect>` +
               `<rect x="${x}" y="${yTop}"  width="${bw}" height="${failH}" fill="rgba(255,100,100,0.7)"></rect>`;
    }).join("");
    const yTicks = [0, max / 2, max].map(v => `
        <line x1="${pad.l}" x2="${pad.l + innerW}" y1="${yOf(v)}" y2="${yOf(v)}"
              stroke="rgba(255,122,31,0.12)" stroke-dasharray="2 4"/>
        <text x="${pad.l - 6}" y="${yOf(v) + 3}" fill="#7a8088"
              font-family="ui-monospace,monospace" font-size="9"
              text-anchor="end">${Math.round(v)}</text>
    `).join("");
    const fmtDay = s => s ? s.slice(5) : "";
    host.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}"
             xmlns="http://www.w3.org/2000/svg">
          ${yTicks}
          ${bars}
          <text x="${pad.l}" y="${h - 8}" fill="#7a8088"
                font-family="ui-monospace,monospace" font-size="9">${fmtDay(merged[0]?.date)}</text>
          <text x="${pad.l + innerW}" y="${h - 8}" fill="#7a8088"
                font-family="ui-monospace,monospace" font-size="9" text-anchor="end">${fmtDay(merged[merged.length - 1]?.date)}</text>
        </svg>
    `;
}

// Pure-SVG line chart for {date, count} arrays. Designed to fit a
// chart-card (200px tall, scales to host width) without external
// dependencies. Bars + smoothed line + 3 y-grid lines + first/last
// date labels. Cyberpunk colour palette.
function renderTimeChart(host, points) {
    if (!host) return;
    const w = host.clientWidth || 320;
    const h = 200;
    const pad = { l: 36, r: 14, t: 16, b: 28 };
    const innerW = w - pad.l - pad.r;
    const innerH = h - pad.t - pad.b;
    const max = Math.max(1, ...points.map(p => p.count));
    const stepX = points.length > 1 ? innerW / (points.length - 1) : 0;
    const yOf = v => pad.t + innerH - (v / max) * innerH;

    // Path for the line.
    const path = points.map((p, i) =>
        `${i === 0 ? "M" : "L"} ${pad.l + i * stepX} ${yOf(p.count)}`
    ).join(" ");
    // Area fill — line + bottom-right + bottom-left + close.
    const area = path +
        ` L ${pad.l + (points.length - 1) * stepX} ${pad.t + innerH}` +
        ` L ${pad.l} ${pad.t + innerH} Z`;

    // Y-axis tick labels (0, max/2, max).
    const yTicks = [0, max / 2, max].map(v => `
        <line x1="${pad.l}" x2="${pad.l + innerW}" y1="${yOf(v)}" y2="${yOf(v)}"
              stroke="rgba(255,122,31,0.12)" stroke-dasharray="2 4"/>
        <text x="${pad.l - 6}" y="${yOf(v) + 3}" fill="#7a8088"
              font-family="ui-monospace,monospace" font-size="9"
              text-anchor="end">${Math.round(v)}</text>
    `).join("");

    // Bars on top of the area for daily granularity.
    const bars = points.map((p, i) => {
        const bw = Math.max(1, stepX * 0.55);
        const x  = pad.l + i * stepX - bw / 2;
        const y  = yOf(p.count);
        return `<rect x="${x}" y="${y}" width="${bw}" height="${pad.t + innerH - y}"
            fill="rgba(255,138,61,0.6)"></rect>`;
    }).join("");

    // First + last date labels.
    const fmtDay = s => s.slice(5);  // "MM-DD"
    const lbls = `
        <text x="${pad.l}" y="${h - 8}" fill="#7a8088"
              font-family="ui-monospace,monospace" font-size="9">${fmtDay(points[0]?.date || "")}</text>
        <text x="${pad.l + innerW}" y="${h - 8}" fill="#7a8088"
              font-family="ui-monospace,monospace" font-size="9" text-anchor="end">${fmtDay(points[points.length - 1]?.date || "")}</text>
    `;

    host.innerHTML = `
        <svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}"
             preserveAspectRatio="none" role="img" aria-label="time series">
            ${yTicks}
            <path d="${area}" fill="rgba(255,138,61,0.12)"/>
            ${bars}
            <path d="${path}" fill="none" stroke="#ff8a3d" stroke-width="1.5"/>
            ${lbls}
        </svg>`;
}

function renderTopStorage(host, rows, totalBytes) {
    if (!host) return;
    if (!rows.length) {
        host.innerHTML = `<p class="settings-hint">No accounts yet.</p>`;
        return;
    }
    const max = Math.max(1, ...rows.map(r => r.used_bytes));
    host.innerHTML = rows.map(r => {
        const pct = Math.round((r.used_bytes / max) * 100);
        const quotaPct = r.quota_bytes ? Math.round((r.used_bytes / r.quota_bytes) * 100) : 0;
        return `
            <div class="storage-row" data-id="${r.account_id}">
                <div class="storage-row-head">
                    <span class="storage-email">${escapeHtml(r.email)}</span>
                    <span class="storage-bytes">${_fmtBytes(r.used_bytes)}
                        <span class="storage-quota">/ ${_fmtBytes(r.quota_bytes)} (${quotaPct}%)</span></span>
                </div>
                <div class="storage-bar"><span style="width:${pct}%"></span></div>
                <div class="storage-meta">${r.message_count} msg${r.message_count === 1 ? "" : "s"}</div>
            </div>`;
    }).join("");
}

async function loadAdminAuditLog() {
    try {
        const rows = await api.get("/admin/audit-log?limit=200");
        const tbody = $("#admin-audit-table tbody");
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty">No admin actions yet.</td></tr>`;
            return;
        }
        const labels = {
            ban_account:     "Ban account",
            unban_account:   "Unban account",
            delete_account:  "Delete account",
            revoke_sessions: "Revoke sessions",
            add_ip_block:    "Add IP block",
            remove_ip_block: "Remove IP block",
        };
        tbody.innerHTML = rows.map(r => `
            <tr>
                <td>${_fmtDate(r.created_at)}</td>
                <td class="email">${escapeHtml(r.admin_email)}</td>
                <td><span class="action-pill">${escapeHtml(labels[r.action] || r.action)}</span></td>
                <td>${escapeHtml(r.target_label || "—")}</td>
                <td>${escapeHtml(r.details || "")}</td>
            </tr>
        `).join("");
    } catch (e) {
        _adminToast("Audit load failed: " + (e.message || e), "err");
    }
}

async function loadAdminAccounts() {
    try {
        const params = new URLSearchParams({
            offset: String(_adminAccountState.offset),
            limit:  String(ADMIN_PAGE_SIZE),
        });
        if (_adminAccountState.q) params.set("q", _adminAccountState.q);
        const r = await api.get("/admin/accounts?" + params.toString());
        _adminAccountState.total = r.total;
        $("#admin-account-total").textContent = `${r.total} match${r.total === 1 ? "" : "es"}`;
        const tbody = $("#admin-accounts-table tbody");
        tbody.innerHTML = r.items.map(a => `
            <tr data-id="${a.id}" data-email="${escapeHtml(a.email)}">
                <td class="email">${escapeHtml(a.email)}</td>
                <td><span class="status-pill ${a.status}">${escapeHtml(a.status)}</span></td>
                <td>${_fmtDate(a.created_at)}</td>
                <td>${_fmtDate(a.last_login_at)}</td>
                <td class="num">${a.message_count}</td>
                <td class="num">${_fmtBytes(a.used_bytes)} / ${_fmtBytes(a.quota_bytes)}</td>
                <td class="row-actions">
                    ${a.status === "banned"
                        ? `<button class="link" data-action="unban">Unban</button>`
                        : `<button class="link" data-action="ban">Ban</button>`}
                    <button class="link" data-action="revoke">Kick</button>
                    <button class="link danger" data-action="delete">Delete</button>
                </td>
            </tr>
        `).join("");
        // Wire actions per row.
        tbody.querySelectorAll("button[data-action]").forEach(btn => {
            btn.addEventListener("click", async () => {
                const tr = btn.closest("tr");
                const id = tr.dataset.id;
                const email = tr.dataset.email;
                const action = btn.dataset.action;
                try {
                    if (action === "ban") {
                        const reason = prompt(`Ban reason for ${email}? (optional)`);
                        if (reason === null) return;
                        await api.post(`/admin/account/${id}/ban`, { reason });
                    } else if (action === "unban") {
                        await api.post(`/admin/account/${id}/unban`, {});
                    } else if (action === "revoke") {
                        if (!confirm(`Force-revoke all live sessions for ${email}?`)) return;
                        const r = await api.post(`/admin/account/${id}/revoke-sessions`, {});
                        _adminToast(`Revoked ${r.revoked} session(s).`, "ok");
                        return;
                    } else if (action === "delete") {
                        if (!confirm(`Delete ${email} and all their data permanently?`)) return;
                        await api.del(`/admin/account/${id}`);
                    }
                    await loadAdminAccounts();
                    _adminToast(`${action} done.`, "ok");
                } catch (e) {
                    _adminToast(`${action} failed: ${e.message || e}`, "err");
                }
            });
        });
        const start = r.total === 0 ? 0 : _adminAccountState.offset + 1;
        const end   = Math.min(_adminAccountState.offset + r.items.length, r.total);
        $("#admin-page-info").textContent = `${start}–${end} of ${r.total}`;
    } catch (e) {
        _adminToast("Accounts load failed: " + (e.message || e), "err");
    }
}

async function loadAdminIpBans() {
    try {
        const rows = await api.get("/admin/ip-blocks");
        const tbody = $("#admin-ipbans-table tbody");
        tbody.innerHTML = rows.length
            ? rows.map(b => `
                <tr data-id="${b.id}">
                    <td class="mono">${escapeHtml(b.fingerprint)}</td>
                    <td>${escapeHtml(b.reason || "")}</td>
                    <td>${_fmtDate(b.created_at)}</td>
                    <td>${b.expires_at ? _fmtDate(b.expires_at) : "—"}</td>
                    <td><button class="link danger" data-action="remove">Remove</button></td>
                </tr>`).join("")
            : `<tr><td colspan="5" class="empty">No IP bans.</td></tr>`;
        tbody.querySelectorAll('button[data-action="remove"]').forEach(btn => {
            btn.addEventListener("click", async () => {
                const id = btn.closest("tr").dataset.id;
                if (!confirm("Remove this IP ban?")) return;
                try {
                    await api.del(`/admin/ip-blocks/${id}`);
                    await loadAdminIpBans();
                    _adminToast("Removed.", "ok");
                } catch (e) {
                    _adminToast("Failed: " + (e.message || e), "err");
                }
            });
        });
    } catch (e) {
        _adminToast("IP bans load failed: " + (e.message || e), "err");
    }
}

// ----------------------------------------------------------------- info-page nav
//
// Click handler for the [HOME]/[ABOUT]/[PRIVACY]/[TERMS] strip at the
// top of the auth card (and the matching nav on each info page, plus
// the "back to sign in" link inside each page body). All targets are
// real SPA views — no full reload, no router. Just delegate via
// data-view attribute and call show().
//
// Auth-related views (auth/unlock/recovery-shown) are skipped here so
// signed-in / mid-flow users aren't booted out of their state by an
// accidental click.
function bindBrandNav() {
    document.body.addEventListener("click", (e) => {
        const a = e.target.closest("a[data-view]");
        if (!a) return;
        const target = a.dataset.view;
        if (!target) return;
        const el = document.getElementById(target);
        if (!el) return;
        e.preventDefault();
        show(target);
        // Update active marker across every brand-nav so the link
        // matching the new view is highlighted.
        document.querySelectorAll(".brand-nav a[data-view]").forEach(link => {
            link.classList.toggle("active", link.dataset.view === target);
        });
        // Restart matrix flag — info pages aren't auth-views so the
        // show() helper already drops the matrix-on class. That's fine.
        window.scrollTo(0, 0);
    });
}

// ----------------------------------------------------------------- onion notice
function _truncateOnion(addr) {
    // v3 .onion addresses are 62 chars (56 hash + ".onion"). They don't
    // fit nicely in a one-line auth card. Show first 14 + … + last 14
    // (= 29 chars visible) — enough to recognise but compact. The full
    // string is still copied to the clipboard on click and lives in the
    // button's title attribute for hover.
    if (!addr || addr.length <= 30) return addr;
    return addr.slice(0, 14) + "…" + addr.slice(-14);
}

function bindOnionNotice(onion) {
    const notice = $("#onion-notice");
    if (!notice) return;
    // Already on the onion — no point showing it.
    const onOnion = location.hostname.endsWith(".onion");
    if (!onion || onOnion) { notice.hidden = true; return; }

    const btn = $("#onion-copy");
    btn.dataset.onion = onion;
    btn.title = onion + " — click to copy. Open in Tor Browser.";
    $("#onion-text").textContent = _truncateOnion(onion);
    notice.hidden = false;

    let resetTimer;
    btn.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(onion);
            scheduleClipboardClear();
            $("#onion-copy-hint").textContent = "copied";
            notice.classList.add("copied");
            clearTimeout(resetTimer);
            resetTimer = setTimeout(() => {
                $("#onion-copy-hint").textContent = "copy";
                notice.classList.remove("copied");
            }, 1800);
        } catch (e) {
            // Fallback: select the text so the user can ctrl+c
            const range = document.createRange();
            range.selectNodeContents($("#onion-text"));
            const sel = getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            toast("Copy with Ctrl+C", "");
        }
    });
}

// ----------------------------------------------------------------- unlock form
function bindUnlock() {
    $("#unlock-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const status = $("#unlock-status");
        const password = new FormData(e.target).get("password");
        setStatus(status, "Decrypting...");
        try {
            await unlockSession(password);
        } catch (err) {
            console.error(err);
            const msg = err.message && err.message.includes("session expired")
                ? err.message
                : "Wrong password.";
            setStatus(status, msg, "err");
            if (err.message && err.message.includes("session expired")) {
                show("auth-view");
                $("#login-form input[name=email]").value = $("#unlock-email").textContent;
                $("#login-form input[name=password]").focus();
            }
        }
    });
    $("#unlock-signout").addEventListener("click", () => {
        clearSession();
        $("#unlock-form").reset();
        setStatus($("#unlock-status"), "");
        show("auth-view");
        $("#login-form input[name=email]").focus();
    });
}

// ----------------------------------------------------------------- boot
async function boot() {
    bindAuthTabs();
    bindCompose();
    bindSearch();
    bindUnlock();
    bindRipples();
    initMatrix();
    startFeaturesLogLoop();
    bindStatusScroller();
    bindBrandNav();
    bindSettings();
    bindAdmin();
    bindComposeExtras();
    bindListControls();
    bindShortcuts();
    applyPrefsToDom();
    // Initial state is auth-view → matrix-on
    document.body.classList.add("matrix-on");

    state.config = await api.config().catch(() => ({
        domain: "qloak.me", domains: ["qloak.me"],
        invite_required: false, captcha_provider: "none",
        onion_address: "",
    }));
    // Lock the signup suffix to the primary domain from /api/v1/config
    // so dev environments (voidmail.local) and prod (qloak.me) both
    // render the right "@..." next to the username field.
    const primaryDomain = state.config.domain || state.config.domains?.[0] || "qloak.me";
    $("#signup-domain-suffix").textContent = "@" + primaryDomain;
    if (state.config.domains && state.config.domains.length > 1) {
        $("#signup-domain-hint").textContent =
            "Other available: " +
            state.config.domains.filter(d => d !== primaryDomain).join(", ");
    } else {
        $("#signup-domain-hint").textContent = "";
    }
    bindOnionNotice(state.config.onion_address);

    $("#login-form").addEventListener("submit", e => {
        e.preventDefault(); handleLogin(e.target);
    });
    $("#signup-form").addEventListener("submit", e => {
        e.preventDefault(); handleSignup(e.target);
    });
    $("#recovery-form").addEventListener("submit", e => {
        e.preventDefault(); handleRecovery(e.target);
    });
    // Live strength meters. The signup meter knows the user's email-
    // to-be (so substring matches get penalised); the recovery meter
    // reads the email field of its own form.
    bindPasswordStrength(
        document.querySelector('#signup-form .pw-strength'),
        () => {
            const uname = document.querySelector('#signup-form input[name="username"]')?.value || "";
            const dom = (state.config?.domain || "qloak.me");
            return uname ? `${uname}@${dom}` : "";
        },
    );
    bindPasswordStrength(
        document.querySelector('#recovery-form .pw-strength'),
        () => document.querySelector('#recovery-form input[name="email"]')?.value || "",
    );
    $("#logout-btn").addEventListener("click", async () => {
        disarmIdleLock();
        try { await api.post("/auth/logout", {}); } catch {}
        try { await Search.clear(); } catch {}
        clearSession();
        api.setToken(null);
        state.account = state.privkey = state.pubkey = null;
        state.searchActive = false;
        $("#search-input").value = "";
        $("#search-stats").textContent = "";
        show("auth-view");
    });

    // Decide which view to show based on what's in storage:
    //   restore  — duration window still open + decrypted key on hand
    //   unlock   — encrypted blob present, ask for password
    //   auth     — nothing usable, show sign-in
    const decision = classifyStoredSession();
    if (decision.kind === "restore") {
        // Skip the unlock prompt and go straight to the inbox.
        try {
            await restoreSession(decision.session);
        } catch (e) {
            console.error("[QloakMail] auto-restore failed:", e);
            // Fallback to unlock prompt
            $("#unlock-email").textContent = decision.session.email;
            const sel = $("#login-remember");
            if (sel) sel.value = decision.session.remember || "";
            show("unlock-view");
            setTimeout(() => $("#unlock-form input[name=password]").focus(), 50);
        }
    } else if (decision.kind === "unlock") {
        $("#unlock-email").textContent = decision.session.email;
        const sel = $("#login-remember");
        if (sel) sel.value = decision.session.remember || "";
        show("unlock-view");
        setTimeout(() => $("#unlock-form input[name=password]").focus(), 50);
    }
    // else "auth" — auth-view is already the default active view.
}

// Restore directly from storage — privkey is already plaintext in the
// stored payload (allowed only when the user picked a duration). No
// password prompt, no SRP. A liveness ping catches an expired
// server-side token and routes back to the auth view.
async function restoreSession(sess) {
    api.setToken(sess.session_token);
    state.account = { account_id: sess.account_id, email: sess.email };
    state.pubkey = await openpgp.readKey({ armoredKey: sess.pubkey_armored });
    state.privkey = await openpgp.readPrivateKey({ armoredKey: sess.privkey_armored });

    try {
        await api.get("/users/me");
    } catch (e) {
        if (e.status === 401) {
            clearSession();
            api.setToken(null);
            state.account = state.privkey = state.pubkey = null;
            show("auth-view");
            toast("Session expired — please sign in again.", "err");
            return;
        }
        // Other errors fall through to enterMailbox which has its own
        // toast on failure.
    }
    await enterMailbox();
}

window.addEventListener("DOMContentLoaded", boot);
