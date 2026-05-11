-- QloakMail schema bootstrap.
-- Loaded by the postgres container on first start.
-- Holds: user accounts, public keys, encrypted private key blobs,
-- SRP verifiers, mailbox metadata. NEVER plaintext mail.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------- accounts ----------
CREATE TABLE IF NOT EXISTS accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           CITEXT UNIQUE NOT NULL,
    -- SRP-6a verifier + salt (RFC 5054, group 2048-bit, SHA-256)
    srp_salt        BYTEA NOT NULL,
    srp_verifier    BYTEA NOT NULL,
    -- OpenPGP public key, ASCII-armored
    pubkey_armored  TEXT  NOT NULL,
    pubkey_fpr      TEXT  NOT NULL,
    -- OpenPGP private key, ASCII-armored, encrypted with Argon2id(password)
    -- and (separately) Argon2id(recovery_code).
    encrypted_privkey_password BYTEA NOT NULL,
    encrypted_privkey_recovery BYTEA NOT NULL,
    -- Argon2id parameters used by the client. Stored so different users may
    -- have different parameters and the server can hand them back at login.
    argon2_params   JSONB NOT NULL,
    -- Storage quota in bytes; 0 = unlimited.
    quota_bytes     BIGINT NOT NULL DEFAULT 1073741824,    -- 1 GiB default
    used_bytes      BIGINT NOT NULL DEFAULT 0,
    status          TEXT  NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','locked','deleted')),
    invite_code     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS accounts_pubkey_fpr_idx ON accounts(pubkey_fpr);

-- ---------- folders ----------
CREATE TABLE IF NOT EXISTS folders (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    system_kind     TEXT,                -- 'inbox' | 'sent' | 'drafts' | 'trash' | 'spam' | NULL
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);

-- ---------- messages (metadata only — body is in the encrypted mailstore) ----------
-- We keep header-only metadata that is unavoidable for IMAP semantics.
-- Subject, From, To, etc. are stored ENCRYPTED to the user's pubkey
-- (i.e. the same envelope that lives in the maildir blob).
CREATE TABLE IF NOT EXISTS messages (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id        UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id         UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    -- Path relative to the maildir of the encrypted message blob.
    storage_path      TEXT NOT NULL,
    size_bytes        BIGINT NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Flags only — \Seen \Answered \Flagged \Draft \Deleted etc.
    flags             TEXT[] NOT NULL DEFAULT '{}',
    -- Opaque, client-supplied search tokens (encrypted, optional).
    -- Used so the inbox listing can render *something* before decryption,
    -- typically a tiny PGP-encrypted JSON {from, subject, date, snippet}.
    encrypted_preview BYTEA
);

CREATE INDEX IF NOT EXISTS messages_account_folder_idx
    ON messages(account_id, folder_id, received_at DESC);

-- ---------- sessions ----------
-- Sessions live in redis (TTL'd, opaque tokens). This table is intentionally
-- minimal: an account_id pointer and an expiry, no IP, no user-agent. We
-- can't subpoena what we don't store.
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash      BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);
CREATE INDEX IF NOT EXISTS sessions_token_idx ON sessions(token_hash);

-- ---------- invite codes ----------
CREATE TABLE IF NOT EXISTS invite_codes (
    code            TEXT PRIMARY KEY,
    note            TEXT,
    max_uses        INTEGER NOT NULL DEFAULT 1,
    uses            INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);

-- ---------- abuse reports ----------
-- REVIEW [MEDIUM]: reported_email / reporter_email are not FK-constrained.
-- Orphaned records if account deleted. Consider FK to accounts(id) with
-- ON DELETE SET NULL, or add unique constraint + app-side validation.
CREATE TABLE IF NOT EXISTS abuse_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reported_email  CITEXT,
    reporter_email  CITEXT,
    body            TEXT NOT NULL,
    headers         TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    handled         BOOLEAN NOT NULL DEFAULT FALSE
);

-- ---------- admin audit log ----------
-- Append-only history of every admin action: bans, unbans, deletes,
-- IP blocks, session revocations. Read-only after insert.
CREATE TABLE IF NOT EXISTS admin_actions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id      UUID NOT NULL,
    admin_email   CITEXT NOT NULL,
    action        TEXT NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    target_label  TEXT,
    details       TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_admin_actions_created ON admin_actions (created_at DESC);

-- ---------- IP block list (admin) ----------
-- Stores ONE-WAY hashes (HMAC-SHA256 keyed with IP_BAN_SECRET) of
-- banned IPs. We never store the IP itself; the admin pastes one in,
-- the API hashes it, the resulting fingerprint is what's compared
-- against incoming requests. Rotating IP_BAN_SECRET invalidates the
-- whole list.
CREATE TABLE IF NOT EXISTS ip_blocks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_hmac     TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_ip_blocks_ip_hmac ON ip_blocks (ip_hmac);

-- ---------- helper: bump a folder's modseq when a message lands ----------
CREATE OR REPLACE FUNCTION touch_account_used_bytes() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE accounts SET used_bytes = used_bytes + NEW.size_bytes
            WHERE id = NEW.account_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE accounts SET used_bytes = GREATEST(0, used_bytes - OLD.size_bytes)
            WHERE id = OLD.account_id;
    END IF;
    RETURN COALESCE(NEW, OLD);
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS messages_quota_trg ON messages;
CREATE TRIGGER messages_quota_trg
    AFTER INSERT OR DELETE ON messages
    FOR EACH ROW EXECUTE FUNCTION touch_account_used_bytes();
