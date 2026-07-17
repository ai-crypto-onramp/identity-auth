-- 0001_init.up.sql
-- Initial schema for the identity-auth service.
-- Conventions: UUID PKs (app-generated UUIDv7), UPPER_CASE enum TEXT (no CHECK),
-- created_at + updated_at on every table, no DB triggers.

BEGIN;

-- User accounts.
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at     TIMESTAMPTZ
);

-- Sessions (refresh-token allowlist; access tokens are stateless JWTs).
CREATE TABLE IF NOT EXISTS sessions (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    issuer             TEXT NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- MFA factors (TOTP).
CREATE TABLE IF NOT EXISTS mfa_factors (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type             TEXT NOT NULL DEFAULT 'TOTP',
    secret_encrypted BYTEA NOT NULL,
    confirmed        BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_factors_user ON mfa_factors(user_id);

-- MFA recovery codes (single-use, hashed).
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

-- Partner API keys (stored as keyed hash; full material revealed once).
CREATE TABLE IF NOT EXISTS api_keys (
    id                UUID PRIMARY KEY,
    partner_id        TEXT NOT NULL,
    prefix            TEXT NOT NULL,
    key_hash          TEXT NOT NULL UNIQUE,
    scopes            JSONB NOT NULL DEFAULT '[]',
    ip_allowlist      JSONB NOT NULL DEFAULT '[]',
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ,
    previous_key_hash TEXT,
    previous_prefix   TEXT,
    rotated_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_partner ON api_keys(partner_id);

-- Roles (seeded).
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Role bindings (subject -> role, optionally scoped).
CREATE TABLE IF NOT EXISTS role_bindings (
    id           UUID PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    role         TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    scope_type   TEXT,
    scope_id     TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_subject ON role_bindings(subject_type, subject_id);

-- Password reset tokens (single-use, hashed).
CREATE TABLE IF NOT EXISTS password_resets (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lockouts (Redis-backed in production; table available as fallback).
CREATE TABLE IF NOT EXISTS lockouts (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit events (append-only; published to audit-event-log via outbox).
CREATE TABLE IF NOT EXISTS audit_events (
    id         UUID PRIMARY KEY,
    type       TEXT NOT NULL,
    subject_id TEXT,
    session_id TEXT,
    request_id TEXT,
    metadata   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject ON audit_events(subject_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(type);

-- Seed predefined roles. Fixed UUIDs so role_bindings can reference them deterministically.
INSERT INTO roles (id, name, permissions, description) VALUES
    ('00000000-0000-7000-8000-000000000001', 'USER',          ARRAY['profile:read','profile:write','session:create','session:read','session:delete'], 'End user'),
    ('00000000-0000-7000-8000-000000000002', 'PARTNER_ADMIN', ARRAY['keys:create','keys:read','keys:rotate','keys:revoke','partner:read','partner:write'], 'Partner administrator'),
    ('00000000-0000-7000-8000-000000000003', 'PARTNER_API',   ARRAY['keys:read','partner:read'], 'Partner API key'),
    ('00000000-0000-7000-8000-000000000004', 'SUPPORT',       ARRAY['users:read','session:read'], 'Support agent'),
    ('00000000-0000-7000-8000-000000000005', 'COMPLIANCE',    ARRAY['users:read','audit:read'], 'Compliance officer'),
    ('00000000-0000-7000-8000-000000000006', 'OPS',           ARRAY['users:unlock','session:read','audit:read'], 'Operations'),
    ('00000000-0000-7000-8000-000000000007', 'ADMIN',         ARRAY['*'], 'Super admin')
ON CONFLICT (name) DO NOTHING;

COMMIT;