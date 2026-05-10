// IndexedDB-backed local search.
//
// The server only ever holds ciphertext, so search has to be fully
// client-side. We keep two object stores:
//
//   messages: { id, subject, from, date, snippet, indexed_at }
//   tokens:   { token, msgId }   (compound key [token, msgId])
//
// Indexing is progressive: every time the user decrypts a message we
// tokenize subject+from+body and write the entries. Tokens use prefix
// matching ("hel" matches "hello") via an IDBKeyRange.bound on the
// tokens index. AND-of-terms is implemented by intersecting the
// per-term result sets.
//
// The DB is namespaced per account — `voidmail:<accountId>` — so that
// shared browsers can't cross-contaminate. clear() deletes the database
// outright on logout.

const DB_PREFIX = "voidmail:";
const DB_VERSION = 1;
const MIN_TOKEN_LEN = 2;
const MAX_TOKEN_LEN = 32;
const SNIPPET_LEN = 240;

let _db = null;
let _accountId = null;

function _dbName(accountId) { return DB_PREFIX + accountId; }

function _tokenize(text) {
    if (!text) return [];
    return Array.from(new Set(
        String(text).toLowerCase()
            .split(/[\W_]+/u)
            .filter(w => w.length >= MIN_TOKEN_LEN && w.length <= MAX_TOKEN_LEN)
    ));
}

function _wrap(req) {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

/** Open (or create) the per-account index database. */
export async function open(accountId) {
    if (_db && _accountId === accountId) return _db;
    if (_db) { _db.close(); _db = null; }
    _accountId = accountId;
    _db = await new Promise((resolve, reject) => {
        const req = indexedDB.open(_dbName(accountId), DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains("messages")) {
                const s = db.createObjectStore("messages", { keyPath: "id" });
                s.createIndex("indexed_at", "indexed_at");
                s.createIndex("date", "date");
            }
            if (!db.objectStoreNames.contains("tokens")) {
                const s = db.createObjectStore("tokens", { keyPath: ["token", "msgId"] });
                s.createIndex("token", "token");
                s.createIndex("msgId", "msgId");
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
    return _db;
}

/** Index (or re-index) a decrypted message. Idempotent. */
export async function indexMessage(id, { subject, from, to, date, body }) {
    if (!_db) return;

    const tokens = _tokenize([subject, from, to, body].filter(Boolean).join(" "));
    const tx = _db.transaction(["messages", "tokens"], "readwrite");
    const msgs = tx.objectStore("messages");
    const toks = tx.objectStore("tokens");

    // Drop any prior token rows for this id (in case the body changed).
    const oldKeys = await new Promise((resolve) => {
        const out = [];
        const req = toks.index("msgId").openKeyCursor(IDBKeyRange.only(id));
        req.onsuccess = (e) => {
            const c = e.target.result;
            if (c) { out.push(c.primaryKey); c.continue(); } else resolve(out);
        };
        req.onerror = () => resolve(out);
    });
    for (const k of oldKeys) toks.delete(k);

    const snippet = (body || "").replace(/\s+/g, " ").trim().slice(0, SNIPPET_LEN);
    msgs.put({
        id,
        subject: subject || "",
        from: from || "",
        date: date || "",
        snippet,
        indexed_at: Date.now(),
    });
    for (const t of tokens) toks.put({ token: t, msgId: id });

    await new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });
}

/** Search returns documents whose tokens prefix-match every search term.
 * Sorted by RFC822 Date header descending. */
export async function search(query) {
    if (!_db || !query) return [];
    const terms = _tokenize(query);
    if (!terms.length) return [];

    const tx = _db.transaction("tokens", "readonly");
    const tokIdx = tx.objectStore("tokens").index("token");

    let acc = null;
    for (const term of terms) {
        const ids = new Set();
        await new Promise((resolve) => {
            // prefix range: [term, term + "￿"]
            const req = tokIdx.openCursor(IDBKeyRange.bound(term, term + "￿"));
            req.onsuccess = (e) => {
                const c = e.target.result;
                if (c) { ids.add(c.value.msgId); c.continue(); } else resolve();
            };
            req.onerror = () => resolve();
        });
        acc = acc === null ? ids : new Set([...acc].filter(x => ids.has(x)));
        if (acc.size === 0) return [];
    }

    if (!acc) return [];
    const tx2 = _db.transaction("messages", "readonly");
    const store = tx2.objectStore("messages");
    const docs = [];
    for (const id of acc) {
        const r = await _wrap(store.get(id));
        if (r) docs.push(r);
    }
    docs.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
    return docs;
}

/** Drop a single message from the index — call when the user deletes it. */
export async function forget(id) {
    if (!_db) return;
    const tx = _db.transaction(["messages", "tokens"], "readwrite");
    const toks = tx.objectStore("tokens");
    const oldKeys = await new Promise((resolve) => {
        const out = [];
        const req = toks.index("msgId").openKeyCursor(IDBKeyRange.only(id));
        req.onsuccess = (e) => {
            const c = e.target.result;
            if (c) { out.push(c.primaryKey); c.continue(); } else resolve(out);
        };
        req.onerror = () => resolve(out);
    });
    for (const k of oldKeys) toks.delete(k);
    tx.objectStore("messages").delete(id);
    await new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

/** Wipe the entire index. Called on logout. */
export async function clear() {
    if (!_db) return;
    const accountId = _accountId;
    _db.close();
    _db = null;
    _accountId = null;
    await new Promise((resolve) => {
        const req = indexedDB.deleteDatabase(_dbName(accountId));
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
        req.onblocked = () => resolve();
    });
}

/** Useful for the UI: how many messages are indexed locally. */
export async function stats() {
    if (!_db) return { messages: 0 };
    const tx = _db.transaction("messages", "readonly");
    const count = await _wrap(tx.objectStore("messages").count());
    return { messages: count };
}

/** Single-message lookup. Returns the cached {subject,from,date,snippet}
 * or null if the message hasn't been opened yet on this device. */
export async function getCached(id) {
    if (!_db) return null;
    const tx = _db.transaction("messages", "readonly");
    const r = await _wrap(tx.objectStore("messages").get(id));
    return r || null;
}

/** Batch lookup. Returns a Map(id → record) for messages that ARE
 * cached. Missing ids are simply absent from the map. */
export async function getCachedBatch(ids) {
    const out = new Map();
    if (!_db || !ids.length) return out;
    const tx = _db.transaction("messages", "readonly");
    const store = tx.objectStore("messages");
    for (const id of ids) {
        const r = await _wrap(store.get(id));
        if (r) out.set(id, r);
    }
    return out;
}
