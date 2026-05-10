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

function show(viewId) {
    $$(".view").forEach(v => v.classList.toggle("active", v.id === viewId));
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
        btn.addEventListener("click", () => {
            $$(".auth-tabs .tab").forEach(b => b.classList.toggle("active", b === btn));
            const target = btn.dataset.tab;
            $$(".auth-form").forEach(f => f.classList.toggle("active", f.id === target + "-form"));
        });
    });
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
        $("#recovery-shown-code").textContent = recoveryCode;
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
                <div class="from"><span class="lock-dot" title="encrypted — click to decrypt">●</span> Encrypted message</div>
                <div class="subject muted">${m.size_bytes} bytes — click to decrypt</div>
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
                    From <strong>${escapeHtml(parsed.from || "")}</strong>
                    to <strong>${escapeHtml(parsed.to || "")}</strong><br>
                    ${escapeHtml(parsed.date || "")}
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
