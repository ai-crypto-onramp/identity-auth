-- 0002_verification_and_refresh.down.sql

BEGIN;

DROP TABLE IF EXISTS used_refresh_tokens;
DROP TABLE IF EXISTS verification_tokens;

COMMIT;