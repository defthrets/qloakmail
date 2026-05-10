-- Migration 003: admin audit log
--
-- Apply on existing deployments:
--   docker compose exec -T postgres \
--       sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
--       < postgres/migrations/003_admin_audit.sql

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
CREATE INDEX IF NOT EXISTS ix_admin_actions_created
    ON admin_actions (created_at DESC);
