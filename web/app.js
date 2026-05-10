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
};

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

// ----------------------------------------------------------------- signup
async function handleSignup(form) {
    const status = $("#signup-status");
    setStatus(status, "Generating keypair (this can take a few seconds)...");

    const fd = new FormData(form);
    const email = fd.get("email").trim();
    const password = fd.get("password");
    const password2 = fd.get("password2");
    const invite = (fd.get("invite") || "").trim();

    if (password !== password2) {
        setStatus(status, "Passwords do not match.", "err");
        return;
    }

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
                await performLogin(email, password, true);
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

// ----------------------------------------------------------------- mailbox
async function enterMailbox() {
    show("mail-view");
    $("#who").textContent = state.account.email;
    armIdleLock();
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
            const { data: plaintext } = await openpgp.decrypt({
                message,
                decryptionKeys: state.privkey,
            });
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

async function renderMessageList() {
    const ul = $("#message-list");
    ul.innerHTML = "";

    if (!state.messages.length) {
        const folder = state.folders.find(f => f.id === state.activeFolderId);
        const isInbox = folder?.system_kind === "inbox";
        const userEmail = state.account?.email || "";
        ul.innerHTML = isInbox ? `
            <li class="empty-state">
                <h4>Your inbox is empty</h4>
                <p>Have a friend send a test to <code>${escapeHtml(userEmail)}</code> — it'll show up here, decrypted in your browser.</p>
            </li>
        ` : `
            <li class="empty-state">
                <h4>Empty folder</h4>
                <p>No messages here yet.</p>
            </li>
        `;
        return;
    }

    // Pull cached previews for every visible message in one IndexedDB
    // pass. Cached records come from past openMessage() decrypts.
    let cached = new Map();
    try {
        cached = await Search.getCachedBatch(state.messages.map(m => m.id));
    } catch (e) {
        console.warn("[QloakMail] preview cache unavailable:", e);
    }

    for (const m of state.messages) {
        const li = document.createElement("li");
        if (!m.flags.includes("\\Seen")) li.classList.add("unread");
        if (m.id === state.selectedMessageId) li.classList.add("active");

        const c = cached.get(m.id);
        if (c) {
            // Decrypted preview available — show real from / subject / snippet.
            const when = c.date ? fmtRelative(c.date) : fmtRelative(m.received_at);
            li.innerHTML = `
                <span class="when">${escapeHtml(when)}</span>
                <div class="from">${escapeHtml(c.from || "(unknown sender)")}</div>
                <div class="subject">${escapeHtml(c.subject || "(no subject)")}</div>
                <div class="snippet">${escapeHtml(c.snippet || "")}</div>
            `;
        } else {
            // Not yet decrypted on this device — render an encrypted
            // placeholder. The lock dot is the "still encrypted" status
            // light, the row stays clickable to decrypt on demand.
            li.classList.add("locked");
            li.innerHTML = `
                <span class="when">${escapeHtml(fmtRelative(m.received_at))}</span>
                <div class="from"><span class="lock-dot" title="encrypted — click to decrypt">●</span> <span class="enc-tag">[ENCRYPTED]</span></div>
                <div class="subject muted">${m.size_bytes}b · tap to decrypt</div>
            `;
        }
        li.addEventListener("click", () => openMessage(m.id));
        ul.appendChild(li);
    }
}

async function openMessage(id) {
    state.selectedMessageId = id;
    // Re-render to set active class on the right li.
    if (!state.searchActive) renderMessageList();

    const view = $("#message-view");
    view.innerHTML = `
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
        const { data: plaintextRfc822 } = await openpgp.decrypt({
            message,
            decryptionKeys: state.privkey,
        });

        const parsed = parseRfc822(plaintextRfc822);
        view.innerHTML = `
            <header>
                <h2>${escapeHtml(parsed.subject || "(no subject)")}</h2>
                <div class="meta">
                    <div><span class="field-tag">[FROM]</span><strong>${escapeHtml(parsed.from || "")}</strong></div>
                    <div><span class="field-tag">[TO]</span><strong>${escapeHtml(parsed.to || "")}</strong></div>
                    <div><span class="field-tag">[DATE]</span>${escapeHtml(parsed.date || "")}</div>
                </div>
            </header>
            <pre class="body-content"></pre>
        `;
        view.querySelector("pre").textContent = parsed.body;

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
            <div class="reader-empty">
                <h3>Decryption failed</h3>
                <p>${escapeHtml(e.message || String(e))}</p>
            </div>
        `;
    }
}

function extractPgpPart(rfc822) {
    const m = rfc822.match(/-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/);
    if (!m) throw new Error("no PGP block found in message");
    return m[0];
}

function parseRfc822(raw) {
    const eol = raw.indexOf("\r\n\r\n");
    const headerBlock = eol >= 0 ? raw.slice(0, eol) : raw;
    const body = eol >= 0 ? raw.slice(eol + 4) : "";
    const headers = {};
    let cur = "";
    for (const line of headerBlock.split(/\r?\n/)) {
        if (/^\s/.test(line) && cur) {
            headers[cur] += " " + line.trim();
        } else {
            const i = line.indexOf(":");
            if (i > 0) {
                cur = line.slice(0, i).toLowerCase();
                headers[cur] = line.slice(i + 1).trim();
            }
        }
    }
    return {
        from: headers.from || "",
        to: headers.to || "",
        subject: headers.subject || "",
        date: headers.date || "",
        body,
    };
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
    setTimeout(() => $("#compose-form input[name=to]").focus(), 50);
}
function closeCompose() {
    $("#compose-modal").hidden = true;
    setStatus($("#compose-status"), "");
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
        const to = fd.get("to").split(",").map(s => s.trim()).filter(Boolean);
        const subject = fd.get("subject") || "";
        const body = fd.get("body") || "";

        setStatus(status, "Sending...");
        try {
            const internalDomains = new Set((state.config?.domains || []).map(d => d.toLowerCase()));
            const isInternal = (addr) => internalDomains.has(addr.split("@")[1]?.toLowerCase());

            const headers = [
                `From: ${state.account.email}`,
                `To: ${to.join(", ")}`,
                `Subject: ${subject}`,
                `Date: ${new Date().toUTCString()}`,
                `Message-ID: <${crypto.randomUUID()}@${state.account.email.split("@")[1]}>`,
                `MIME-Version: 1.0`,
                `Content-Type: text/plain; charset=utf-8`,
            ].join("\r\n");
            const rfc822 = headers + "\r\n\r\n" + body;

            await api.post("/mail/send", {
                rfc822_b64: b64encode(new TextEncoder().encode(rfc822)),
                rcpt_to: to,
                is_internal_only: to.every(isInternal),
            });
            setStatus(status, "Sent.", "ok");
            toast("Message sent", "ok");
            setTimeout(() => {
                closeCompose();
                e.target.reset();
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
    // Initial state is auth-view → matrix-on
    document.body.classList.add("matrix-on");

    state.config = await api.config().catch(() => ({
        domain: "qloak.me", domains: ["qloak.me"],
        invite_required: false, captcha_provider: "none",
        onion_address: "",
    }));
    $("#signup-domain-hint").textContent =
        "Domain: " + state.config.domains.join(", ");
    if (state.config.invite_required) $("#invite-row").hidden = false;
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
