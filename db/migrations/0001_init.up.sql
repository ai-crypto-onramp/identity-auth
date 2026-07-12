-- 0001_init.up.sql
-- Initial schema for the identity-auth service.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- User accounts.
CREATE TABLE IF NOT EXISTS users (
    id            text PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','active','locked','suspended','closed')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    closed_at     timestamptz
);

-- Sessions (refresh-token allowlist; access tokens are stateless JWTs).
CREATE TABLE IF NOT EXISTS sessions (
    id                 text PRIMARY KEY,
    user_id            text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash text NOT NULL UNIQUE,
    issuer             text NOT NULL,
    issued_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    revoked_at         timestamptz
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- MFA factors (TOTP).
CREATE TABLE IF NOT EXISTS mfa_factors (
    id               text PRIMARY KEY,
    user_id          text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type             text NOT NULL DEFAULT 'totp',
    secret_encrypted bytea NOT NULL,
    confirmed        boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    disabled_at      timestamptz
);
CREATE INDEX IF NOT EXISTS idx_mfa_factors_user ON mfa_factors(user_id);

-- MFA recovery codes (single-use, hashed).
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id        text PRIMARY KEY,
    user_id   text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at   timestamptz
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

-- Partner API keys (stored as keyed hash; full material revealed once).
CREATE TABLE IF NOT EXISTS api_keys (
    id                text PRIMARY KEY,
    partner_id        text NOT NULL,
    prefix            text NOT NULL,
    key_hash          text NOT NULL UNIQUE,
    scopes            jsonb NOT NULL DEFAULT '[]',
    ip_allowlist      jsonb NOT NULL DEFAULT '[]',
    expires_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at        timestamptz,
    previous_key_hash text,
    previous_prefix   text,
    rotated_at         timestamptz
);
CREATE INDEX IF NOT EXISTS idx_api_keys_partner ON api_keys(partner_id);

-- Roles (seeded).
CREATE TABLE IF NOT EXISTS roles (
    id          text PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    permissions text[] NOT NULL DEFAULT '{}',
    description text
);

-- Role bindings (subject -> role, optionally scoped).
CREATE TABLE IF NOT EXISTS role_bindings (
    id           text PRIMARY KEY,
    subject_type text NOT NULL CHECK (subject_type IN ('user','api_key')),
    subject_id   text NOT NULL,
    role         text NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    scope_type   text,
    scope_id     text,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_subject ON role_bindings(subject_type, subject_id);

-- Password reset tokens (single-use, hashed).
CREATE TABLE IF NOT EXISTS password_resets (
    id         text PRIMARY KEY,
    user_id    text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

-- Lockouts (Redis-backed in production; table available as fallback).
CREATE TABLE IF NOT EXISTS lockouts (
    user_id      text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    fail_count   integer NOT NULL DEFAULT 0,
    locked_until timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Audit events (append-only; published to audit-event-log via outbox).
CREATE TABLE IF NOT EXISTS audit_events (
    id         text PRIMARY KEY,
    type       text NOT NULL,
    subject_id text,
    session_id text,
    request_id text,
    metadata   jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject ON audit_events(subject_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(type);

-- Seed predefined roles.
INSERT INTO roles (id, name, permissions, description) VALUES
    ('r_user',         'user',          ARRAY['profile:read','profile:write','session:create','session:read','session:delete'], 'End user'),
    ('r_partner_admin','partner_admin', ARRAY['keys:create','keys:read','keys:rotate','keys:revoke','partner:read','partner:write'], 'Partner administrator'),
    ('r_partner_api',  'partner_api',   ARRAY['keys:read','partner:read'], 'Partner API key'),
    ('r_support',      'support',       ARRAY['users:read','session:read'], 'Support agent'),
    ('r_compliance',   'compliance',    ARRAY['users:read','audit:read'], 'Compliance officer'),
    ('r_ops',          'ops',           ARRAY['users:unlock','session:read','audit:read'], 'Operations'),
    ('r_admin',        'admin',         ARRAY['*'], 'Super admin')
ON CONFLICT (name) DO NOTHING;

COMMIT;