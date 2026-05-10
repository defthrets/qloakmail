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
async function performLogin(email, password) {
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
    await enterMailbox();
}

async function handleLogin(form) {
    const status = $("#login-status");
    const fd = new FormData(form);
    const email = fd.get("email").trim();
    const password = fd.get("password");

    setStatus(status, "Authenticating...");
    try {
        await performLogin(email, password);
    } catch (e) {
        console.error(e);
        setStatus(status, "Sign-in failed: " + (e.message || e), "err");
    }
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
                await performLogin(email, password);
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
            await performLogin(email, newPassword);
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
    renderMessageList();
    renderEmptyReader();
}

function renderEmptyReader() {
    $("#message-view").innerHTML = `
        <div class="reader-empty">
            <h3>Select a message</h3>
            <p>Choose an email from the list, or compose a new one.</p>
        </div>
    `;
}

function renderMessageList() {
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

    for (const m of state.messages) {
        const li = document.createElement("li");
        if (!m.flags.includes("\\Seen")) li.classList.add("unread");
        if (m.id === state.selectedMessageId) li.classList.add("active");
        li.innerHTML = `
            <span class="when">${escapeHtml(fmtRelative(m.received_at))}</span>
            <div class="from">[encrypted]</div>
            <div class="subject">${m.size_bytes} bytes</div>
        `;
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

// ----------------------------------------------------------------- boot
async function boot() {
    bindAuthTabs();
    bindCompose();
    bindSearch();

    state.config = await api.config().catch(() => ({
        domain: "qloak.me", domains: ["qloak.me"],
        invite_required: false, captcha_provider: "none",
    }));
    $("#signup-domain-hint").textContent =
        "Domain: " + state.config.domains.join(", ");
    if (state.config.invite_required) $("#invite-row").hidden = false;

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
        api.setToken(null);
        state.account = state.privkey = state.pubkey = null;
        state.searchActive = false;
        $("#search-input").value = "";
        $("#search-stats").textContent = "";
        show("auth-view");
    });
}

window.addEventListener("DOMContentLoaded", boot);
