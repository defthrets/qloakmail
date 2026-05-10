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

function fmtRelative(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    const now = new Date();
    const sec = (now - d) / 1000;
    if (sec < 60) return "just now";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    if (sec < 86400 * 7) return Math.floor(sec / 86400) + "d";
    return d.toLocaleDateString();
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
        // 1) OpenPGP keypair
        const { privateKey, publicKey } = await openpgp.generateKey({
            type: "ecc",
            curve: "ed25519",
            userIDs: [{ email }],
            format: "armored",
        });
        const pubObj = await openpgp.readKey({ armoredKey: publicKey });
        const fpr = pubObj.getFingerprint();

        // 2) Recovery code
        const recoveryCode = generateRecoveryCode();

        // 3) Wrap private key with both password and recovery code
        const wrappedPwd = await wrapPrivateKey(privateKey, password);
        const wrappedRec = await wrapPrivateKey(privateKey, recoveryCode, {
            ...wrappedPwd.argon2_params,
            // Different salt for the recovery wrap.
            salt_b64: b64encode(_internals.randomBytes(16)),
        });

        // 4) SRP verifier
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

        // 5) Show recovery code (one-time)
        $("#recovery-shown-code").textContent = recoveryCode;
        show("recovery-shown-view");
        $("#recovery-shown-confirm").addEventListener("change", e => {
            $("#recovery-shown-continue").disabled = !e.target.checked;
        }, { once: true });
        $("#recovery-shown-continue").addEventListener("click", () => {
            show("auth-view");
            // Pre-fill login form.
            $("#login-form input[name=email]").value = email;
            $("#login-form input[name=password]").focus();
        }, { once: true });
    } catch (e) {
        console.error(e);
        setStatus(status, "Failed: " + (e.message || e), "err");
    }
}

// ----------------------------------------------------------------- login
async function handleLogin(form) {
    const status = $("#login-status");
    const fd = new FormData(form);
    const email = fd.get("email").trim();
    const password = fd.get("password");

    setStatus(status, "Authenticating...");
    try {
        // 1) /login/init
        const init = await api.post("/auth/login/init", { email });

        // 2) Build SRP session, compute A and M1
        const session = await SRP.startClient(email, password);
        const { M1Hex } = await session.processChallenge(init.srp_salt, init.srp_B);
        const A = session.getA();

        // 3) /login/verify
        const v = await api.post("/auth/login/verify", {
            session_id: init.session_id,
            srp_A: A,
            srp_M1: M1Hex,
        });
        if (!session.verifyServer(v.srp_M2)) {
            throw new Error("server proof failed — possible MITM");
        }

        // 4) Decrypt the private-key blob
        const privArmored = await unwrapPrivateKey(
            v.encrypted_privkey_password, password, v.argon2_params
        );

        api.setToken(v.session_token);
        state.account = { account_id: v.account_id, email: v.email };
        state.pubkey = await openpgp.readKey({ armoredKey: v.pubkey_armored });
        state.privkey = await openpgp.readPrivateKey({ armoredKey: privArmored });

        await enterMailbox();
    } catch (e) {
        console.error(e);
        setStatus(status, "Sign-in failed: " + (e.message || e), "err");
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

        // Re-wrap with the new password and rotate SRP verifier.
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

        setStatus(status, "Password reset. Sign in with the new password.", "ok");
        $$(".auth-tabs .tab").forEach(b => b.classList.toggle("active", b.dataset.tab === "login"));
        $$(".auth-form").forEach(f => f.classList.toggle("active", f.id === "login-form"));
        $("#login-form input[name=email]").value = email;
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
    await loadFolders();
    if (state.folders.length) {
        const inbox = state.folders.find(f => f.system_kind === "inbox") || state.folders[0];
        await selectFolder(inbox.id);
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
        li.textContent = f.name;
        if (f.id === state.activeFolderId) li.classList.add("active");
        const count = document.createElement("span");
        count.className = "count";
        count.textContent = f.unread_count
            ? `${f.unread_count}/${f.total_count}` : `${f.total_count}`;
        li.appendChild(count);
        li.addEventListener("click", () => selectFolder(f.id));
        ul.appendChild(li);
    }
}

async function selectFolder(folderId) {
    state.activeFolderId = folderId;
    $$("#folder-list li").forEach((li, i) =>
        li.classList.toggle("active", state.folders[i].id === folderId));
    state.messages = await api.get(`/mail/folders/${folderId}/messages`);
    // Leaving search context — reset the box.
    state.searchActive = false;
    const input = $("#search-input");
    if (input.value) input.value = "";
    await refreshSearchStats();
    renderMessageList();
    $("#message-view").innerHTML = `<p style="color:var(--fg-dim)">Select a message.</p>`;
}

function renderMessageList() {
    const ul = $("#message-list");
    ul.innerHTML = "";
    for (const m of state.messages) {
        const li = document.createElement("li");
        if (!m.flags.includes("\\Seen")) li.classList.add("unread");
        // We don't decrypt every preview eagerly — show placeholder + size.
        li.innerHTML = `
            <span class="when">${fmtRelative(m.received_at)}</span>
            <div class="from">[encrypted]</div>
            <div class="subject">${m.size_bytes} bytes</div>
        `;
        li.addEventListener("click", () => openMessage(m.id));
        ul.appendChild(li);
    }
    if (!state.messages.length) {
        ul.innerHTML = `<li style="color:var(--fg-dim);cursor:default">Empty folder.</li>`;
    }
}

async function openMessage(id) {
    state.selectedMessageId = id;
    const view = $("#message-view");
    view.innerHTML = `<p style="color:var(--fg-dim)">Decrypting...</p>`;
    try {
        const msg = await api.get(`/mail/messages/${id}`);
        const blob = b64decode(msg.encrypted_blob_b64);
        const armored = new TextDecoder().decode(blob);

        // The blob is an RFC 3156 multipart/encrypted MIME message. Pull
        // the application/octet-stream part out and ask OpenPGP to decrypt.
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
                    <strong>${escapeHtml(parsed.from || "")}</strong>
                    &nbsp;->&nbsp; ${escapeHtml(parsed.to || "")}
                    <br>
                    <span>${escapeHtml(parsed.date || "")}</span>
                </div>
            </header>
            <pre></pre>
        `;
        view.querySelector("pre").textContent = parsed.body;

        if (!msg.flags.includes("\\Seen")) {
            await api.post(`/mail/messages/${id}/flags`, { add: ["\\Seen"], remove: [] });
            await loadFolders();
        }

        // Add to the local IndexedDB search index. Best-effort — never
        // block the read.
        try {
            await Search.indexMessage(id, parsed);
            await refreshSearchStats();
        } catch (e) {
            console.warn("[QloakMail] indexing failed:", e);
        }
    } catch (e) {
        console.error(e);
        view.innerHTML = `<p style="color:var(--warn)">Decryption failed: ${escapeHtml(e.message || String(e))}</p>`;
    }
}

function extractPgpPart(rfc822) {
    // The PGP part begins with "-----BEGIN PGP MESSAGE-----" and ends
    // with "-----END PGP MESSAGE-----".
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

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
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
        ul.innerHTML = `<li style="color:var(--fg-dim);cursor:default;padding:0.7rem 0.9rem">
            No matches in your locally indexed mail.<br>
            <small>Open messages once to add them to the search index.</small>
        </li>`;
        return;
    }

    for (const r of results) {
        const li = document.createElement("li");
        li.className = "search-result";
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
function bindCompose() {
    $("#compose-btn").addEventListener("click", () => {
        $("#compose-modal").hidden = false;
        $("#compose-form input[name=to]").focus();
    });
    $("#compose-close").addEventListener("click", () => {
        $("#compose-modal").hidden = true;
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
            // Build the RFC822 message. For internal recipients, encrypt the
            // entire body+headers with their pubkey (we let the encrypt-pipe
            // do the actual delivery encryption — but if EVERY recipient is
            // internal we can also pre-encrypt to provide deniability).
            const internalDomains = new Set(state.config.domains.map(d => d.toLowerCase()));
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
            setTimeout(() => {
                $("#compose-modal").hidden = true;
                e.target.reset();
                setStatus(status, "");
            }, 800);
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
        domain: "voidmail.local", domains: ["voidmail.local"],
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
