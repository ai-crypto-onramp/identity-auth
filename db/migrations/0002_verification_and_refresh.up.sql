-- 0002_verification_and_refresh.up.sql
-- Email verification tokens + refresh-token reuse-detection ledger.

BEGIN;

CREATE TABLE IF NOT EXISTS verification_tokens (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_user ON verification_tokens(user_id);

CREATE TABLE IF NOT EXISTS used_refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;