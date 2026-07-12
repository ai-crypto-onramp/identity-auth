-- 0001_init.down.sql
-- Reverse of 0001_init.up.sql.

BEGIN;

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS lockouts;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS role_bindings;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_factors;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

COMMIT;