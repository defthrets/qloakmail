// Thin REST wrapper. Holds the session token in memory only — never in
// localStorage, so a closed tab logs you out (mirrors Proton's behaviour).

const BASE = "/api/v1";
let _token = null;

function setToken(t) { _token = t; }
function getToken() { return _token; }

async function request(path, opts = {}) {
    const headers = new Headers(opts.headers || {});
    if (!headers.has("Content-Type") && opts.body) {
        headers.set("Content-Type", "application/json");
    }
    if (_token) headers.set("Authorization", "Bearer " + _token);

    const r = await fetch(BASE + path, { ...opts, headers });
    if (r.status === 204) return null;
    const ct = r.headers.get("Content-Type") || "";
    const body = ct.includes("json") ? await r.json() : await r.text();
    if (!r.ok) {
        const err = new Error(typeof body === "string"
            ? body
            : (body.detail || JSON.stringify(body)));
        err.status = r.status;
        err.body = body;
        throw err;
    }
    return body;
}

export const api = {
    setToken, getToken,
    get: (p) => request(p),
    post: (p, body) => request(p, { method: "POST", body: JSON.stringify(body) }),
    put: (p, body) => request(p, { method: "PUT", body: JSON.stringify(body) }),
    del: (p) => request(p, { method: "DELETE" }),
    config: () => request("/config"),
};
