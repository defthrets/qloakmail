-- Migration 002: admin panel — IP block list table
--
-- Apply on existing deployments (init.sql only runs on first start
-- of a fresh postgres volume):
--
--     docker compose exec -T postgres \
--         psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--         < postgres/migrations/002_admin_panel.sql
--
-- Idempotent — safe to run multiple times.

CREATE TABLE IF NOT EXISTS ip_blocks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_hmac     TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_ip_blocks_ip_hmac ON ip_blocks (ip_hmac);
