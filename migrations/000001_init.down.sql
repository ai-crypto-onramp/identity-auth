-- Down migration for Stage 1: drop all tables, types, and the extension.

DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS role_bindings;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_factors;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS role_binding_scope_type;
DROP TYPE IF EXISTS role_binding_subject_type;
DROP TYPE IF EXISTS mfa_factor_type;
DROP TYPE IF EXISTS user_status;

DROP EXTENSION IF EXISTS "pgcrypto";