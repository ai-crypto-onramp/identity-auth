-- Stage 1: DB schema for the Identity & Auth service.
-- Implements the durable data model described in README.md.

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Enumerations
-- ---------------------------------------------------------------------------

CREATE TYPE user_status AS ENUM ('pending', 'active', 'locked', 'suspended', 'closed');

CREATE TYPE mfa_factor_type AS ENUM ('totp');

CREATE TYPE role_binding_subject_type AS ENUM ('user', 'api_key');

CREATE TYPE role_binding_scope_type AS ENUM ('global', 'partner', 'resource');

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text         NOT NULL UNIQUE,
    password_hash text         NOT NULL,
    status        user_status  NOT NULL DEFAULT 'pending',
    created_at    timestamptz  NOT NULL DEFAULT now(),
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    closed_at     timestamptz
);

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_created_at_idx ON users (created_at);

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id                 uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_token_hash text         NOT NULL,
    issuer             text         NOT NULL,
    issued_at          timestamptz  NOT NULL DEFAULT now(),
    last_seen_at       timestamptz  NOT NULL DEFAULT now(),
    expires_at         timestamptz  NOT NULL,
    revoked_at         timestamptz
);

CREATE INDEX sessions_user_id_idx        ON sessions (user_id);
CREATE INDEX sessions_refresh_token_idx  ON sessions (refresh_token_hash);
CREATE INDEX sessions_expires_at_idx     ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- mfa_factors
-- ---------------------------------------------------------------------------
CREATE TABLE mfa_factors (
    id               uuid             PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid             NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type             mfa_factor_type  NOT NULL DEFAULT 'totp',
    secret_encrypted bytea            NOT NULL,
    confirmed        boolean          NOT NULL DEFAULT false,
    created_at       timestamptz      NOT NULL DEFAULT now(),
    disabled_at      timestamptz
);

CREATE INDEX mfa_factors_user_id_idx ON mfa_factors (user_id);

-- ---------------------------------------------------------------------------
-- mfa_recovery_codes
-- ---------------------------------------------------------------------------
CREATE TABLE mfa_recovery_codes (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  text         NOT NULL,
    used_at    timestamptz
);

CREATE INDEX mfa_recovery_codes_user_id_idx ON mfa_recovery_codes (user_id);
CREATE INDEX mfa_recovery_codes_code_idx   ON mfa_recovery_codes (code_hash);

-- ---------------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    partner_id   uuid         NOT NULL,
    prefix       text         NOT NULL,
    key_hash     text         NOT NULL,
    scopes       jsonb        NOT NULL DEFAULT '[]'::jsonb,
    ip_allowlist jsonb        NOT NULL DEFAULT '[]'::jsonb,
    expires_at   timestamptz,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

CREATE INDEX api_keys_partner_id_idx ON api_keys (partner_id);
CREATE INDEX api_keys_prefix_idx     ON api_keys (prefix);

-- ---------------------------------------------------------------------------
-- roles
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text         NOT NULL UNIQUE,
    permissions text[]       NOT NULL DEFAULT '{}',
    description text         NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------------------
-- role_bindings
-- ---------------------------------------------------------------------------
CREATE TABLE role_bindings (
    id           uuid                       PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type role_binding_subject_type NOT NULL,
    subject_id   uuid                       NOT NULL,
    role_id      uuid                       NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    scope_type   role_binding_scope_type    NOT NULL DEFAULT 'global',
    scope_id     uuid,
    created_at   timestamptz                NOT NULL DEFAULT now()
);

CREATE INDEX role_bindings_subject_idx ON role_bindings (subject_type, subject_id);
CREATE INDEX role_bindings_role_idx    ON role_bindings (role_id);

-- ---------------------------------------------------------------------------
-- password_resets
-- ---------------------------------------------------------------------------
CREATE TABLE password_resets (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash text         NOT NULL,
    expires_at timestamptz  NOT NULL,
    used_at    timestamptz
);

CREATE INDEX password_resets_user_id_idx   ON password_resets (user_id);
CREATE INDEX password_resets_token_idx    ON password_resets (token_hash);
CREATE INDEX password_resets_expires_at_idx ON password_resets (expires_at);

-- ---------------------------------------------------------------------------
-- Seed predefined roles and the fixed permission enumeration.
-- ---------------------------------------------------------------------------
INSERT INTO roles (name, permissions, description) VALUES
    ('user',          ARRAY['profile:read','profile:write','sessions:read','sessions:write'], 'Default end-user role.'),
    ('partner_admin', ARRAY['keys:read','keys:create','keys:rotate','keys:revoke','tx:read','tx:create'], 'Partner administrator.'),
    ('partner_api',  ARRAY['tx:read','tx:create','kyc:read'], 'Partner API key role.'),
    ('support',      ARRAY['users:read','sessions:read','kyc:read'], 'Support agent role.'),
    ('compliance',   ARRAY['users:read','tx:read','kyc:read','audit:read'], 'Compliance officer role.'),
    ('ops',          ARRAY['users:read','users:write','sessions:read','sessions:revoke','keys:read'], 'Operations role.'),
    ('admin',        ARRAY['users:read','users:write','sessions:read','sessions:revoke','keys:read','keys:create','keys:rotate','keys:revoke','tx:read','tx:create','kyc:read','audit:read','rbac:read','rbac:write'], 'Super administrator role.');