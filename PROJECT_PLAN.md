# Project Plan — Identity & Auth

This plan implements the Identity & Auth service as specified in `README.md`. It
covers the full user account lifecycle, session/JWT management, MFA enrollment,
partner API keys, RBAC, audit emission, observability, test coverage, and
Docker/CI hardening. Stages are ordered so each builds on the primitives
introduced by the previous one, with persistence and core auth primitives
landing first.

## Stage 1: DB Schema & Migrations

**Goal:** Establish the PostgreSQL schema and migration tooling for all durable
entities described in the README data model.

**Tasks:**
- [ ] Choose a migration tool (e.g. `golang-migrate`) and add it to `Makefile`/CI.
- [ ] Create `migrations/` directory with ordered up/down SQL files.
- [ ] Add `users` table (id, email unique, password_hash, status enum, timestamps, closed_at).
- [ ] Add `sessions` table (id, user_id FK, refresh_token_hash, issuer, issued_at, last_seen_at, expires_at, revoked_at).
- [ ] Add `mfa_factors` and `mfa_recovery_codes` tables (secret_encrypted, confirmed, disabled_at, code_hash, used_at).
- [ ] Add `api_keys` table (id, partner_id, prefix, key_hash, scopes jsonb, ip_allowlist, expires_at, revoked_at).
- [ ] Add `roles` and `role_bindings` tables with subject_type/scope_type enums.
- [ ] Add `password_resets` table (token_hash, expires_at, used_at).
- [ ] Seed predefined roles (`user`, `partner_admin`, `partner_api`, `support`, `compliance`, `ops`, `admin`) and the fixed permission enumeration.
- [ ] Add a Go-side `db` package with connection pooling (`pgx`/`database/sql`) and config from `DB_URL`.
- [ ] Add column-level encryption helpers (TDE / envelope encryption) for `secret_encrypted`, `key_hash`, recovery code hashes.

**Acceptance criteria:**
- `make migrate-up` and `make migrate-down` apply cleanly against an empty Postgres instance.
- All tables and indexes from the README data model exist with correct types and constraints.
- Seeded roles are queryable via `SELECT * FROM roles`.
- Encryption helpers round-trip secrets in unit tests.

## Stage 2: User Registration & Password Hashing

**Goal:** Implement the account lifecycle endpoints and password hashing with
Argon2id (bcrypt fallback) per the README stack.

**Tasks:**
- [ ] Implement Argon2id hasher with tunable `ARGON2_*` params and bcrypt fallback at `BCRYPT_COST`.
- [ ] Add password policy enforcement (`PASSWORD_MIN_LENGTH`, breach-list hashed lookup).
- [ ] Implement `POST /v1/users` (registration) producing `pending` status + signed email-verification token.
- [ ] Implement email verification flow updating `status` to `active`.
- [ ] Implement `GET /v1/users/me` and `PATCH /v1/users/me` with field-level audit stubs.
- [ ] Implement soft-delete/closure path setting `closed_at` and `status=closed`.
- [ ] Add account state machine (`pending` → `active` → `locked`/`suspended` → `closed`) with guard middleware.
- [ ] Add standard error envelope `{ "error": { "code", "message", "request_id" } }` and `request_id` middleware.

**Acceptance criteria:**
- Registering a user returns a `pending` account with hashed password; plaintext never logged.
- Email verification flips status to `active`.
- Password policy rejects short / breached passwords.
- Profile update emits an audit record per changed field.
- Soft-deleted users retain audit stub; further login refused.

## Stage 3: Sessions & JWT (Login / Refresh / Logout)

**Goal:** Implement session lifecycle with short-lived ES256 JWT access tokens
and rotating opaque refresh tokens backed by Redis allowlist.

**Tasks:**
- [ ] Implement ES256 JWT signer/verifier using `JWT_SIGNING_KEY` / `JWT_SIGNING_KEY_PATH`.
- [ ] Implement `POST /v1/sessions` (login) issuing access + refresh tokens.
- [ ] Implement `POST /v1/sessions/refresh` with rotation: invalidate old, issue new, update Redis allowlist.
- [ ] Implement `DELETE /v1/sessions` (logout) and `DELETE /v1/sessions/{id}` (revoke).
- [ ] Implement `GET /v1/sessions` listing active sessions for the user.
- [ ] Store refresh-token hashes in `sessions` and allowlist entries in Redis with TTL = `SESSION_IDLE_TIMEOUT` and absolute `JWT_REFRESH_TTL`.
- [ ] Enforce concurrent session limits and idle/absolute timeouts via Redis TTL.
- [ ] Add `Authorization: Bearer <jwt>` middleware resolving subject + session.
- [ ] Emit `auth.login`, `auth.logout`, `auth.refresh` audit events.

**Acceptance criteria:**
- Login returns ES256-signed JWT with `sub`, `sid`, `scope`, `roles`, `exp`, `iat`, `iss`.
- Refresh rotates the token; reused old refresh token is rejected and revokes the chain.
- Logout revokes the session in DB and Redis.
- Idle/absolute timeout enforced server-side.
- p99 login latency < 30 ms (excluding MFA) in a local bench.

## Stage 4: MFA Enrollment & Verification

**Goal:** Implement TOTP MFA enrollment, verification, recovery codes, and
login-time MFA challenge per the README MFA section.

**Tasks:**
- [ ] Implement TOTP secret generation + QR rendering (`otp` library, `MFA_ISSUER`, `MFA_WINDOW`).
- [ ] Implement `POST /v1/mfa/enroll` returning secret + QR; store `secret_encrypted`.
- [ ] Implement `POST /v1/mfa/verify` requiring two consecutive valid OTPs before setting `confirmed=true`.
- [ ] Require MFA challenge on `POST /v1/sessions` when any active factor exists.
- [ ] Implement recovery code generation (single-use, hashed), `POST /v1/mfa/recovery` re-issue with re-auth.
- [ ] Implement `DELETE /v1/mfa/factors/{id}` with re-auth requirement.
- [ ] Emit `auth.mfa.enroll` and `auth.mfa.verify` audit events.

**Acceptance criteria:**
- Enrollment yields a scannable QR and a hashed secret; full secret never retrievable again.
- Factor activates only after two consecutive valid OTPs.
- Login with an enrolled factor requires an OTP challenge; wrong OTP increments lockout counter.
- Recovery codes are single-use; re-issue invalidates prior codes.
- Disable factor requires recent re-auth and emits an audit event.

## Stage 5: Partner API Keys

**Goal:** Implement partner API key issuance, rotation, revocation, and scoped
authentication per the partner API key section of the README.

**Tasks:**
- [ ] Implement high-entropy opaque key generator with stable prefix for lookup.
- [ ] Store only keyed hash (`key_hash`) plus prefix; reveal full key material exactly once.
- [ ] Implement `POST /v1/api-keys` (admin / `partner_admin`) with scopes, expiry, IP allowlist.
- [ ] Implement `GET /v1/api-keys` scoped to caller's partner.
- [ ] Implement `POST /v1/api-keys/{id}/rotate` with dual-active window, then revoke old.
- [ ] Implement `DELETE /v1/api-keys/{id}` revocation.
- [ ] Expose key prefix resolution + scope/role evaluation for `api-gateway` via `/v1/authz`.
- [ ] Emit `auth.key.use` and `auth.key.rotate` audit events.

**Acceptance criteria:**
- Key material shown once at issuance; subsequent reads return only prefix + metadata.
- Scopes (partner ID, role set, expiry, IP allowlist) enforced at decision time.
- Rotation supports a dual-active window; old key revocable after cutover.
- Revoked keys fail authz with an audited deny decision.

## Stage 6: RBAC Roles, Bindings & Authz Endpoint

**Goal:** Implement the role/permission model, bindings, and the `/v1/authz`
decision endpoint plus OPA bundle generation.

**Tasks:**
- [ ] Codify the fixed permission enumeration and role → permissions mapping in Go.
- [ ] Implement `GET /v1/roles` listing roles and permissions.
- [ ] Implement `POST /v1/role-bindings`, `GET /v1/role-bindings`, `DELETE /v1/role-bindings/{id}`.
- [ ] Compute effective permissions as union of bound role permissions intersected with scope.
- [ ] Implement `POST /v1/authz` returning `{ "allow": bool, "reason": [...] }`.
- [ ] Add `cmd/gen-rbac-bundle` generating `rbac.rego` OPA bundle for `api-gateway`.
- [ ] Emit `auth.authz.deny` audit events for negative decisions.

**Acceptance criteria:**
- All predefined roles are seeded and listed by `/v1/roles`.
- Bindings can be created/listed/deleted scoped by partner/resource.
- `/v1/authz` returns correct allow/deny for sample subjects, actions, resources.
- Generated `rbac.rego` loads cleanly in OPA and produces identical decisions.

## Stage 7: Password Reset & Account Lockout

**Goal:** Implement password reset flows and Redis-backed account lockout with
exponential backoff per the README.

**Tasks:**
- [ ] Implement `POST /v1/password/reset/init` issuing single-use short-TTL token bound to user+intent.
- [ ] Implement `POST /v1/password/reset/confirm` requiring MFA re-auth when enrolled; invalidates all sessions on success.
- [ ] Implement Redis-backed lockout counter with `LOCKOUT_THRESHOLD` and exponential backoff (`LOCKOUT_BASE_SECONDS`).
- [ ] Block token issuance for locked accounts; revoke refresh tokens on lock.
- [ ] Implement admin unlock path with mandatory audit record.
- [ ] Emit `auth.lockout` audit events.

**Acceptance criteria:**
- Reset token is single-use and expires per TTL; re-auth via MFA enforced when enrolled.
- Successful password change revokes all active sessions for the user.
- N consecutive failures lock the account with exponential backoff.
- Admin unlock emits an audit record and clears Redis counter.
- Locked accounts cannot issue or refresh tokens.

## Stage 8: Audit Event Emission

**Goal:** Wire a consistent audit-event emitter into every auth path and publish
to the event bus topic consumed by `audit-event-log`.

**Tasks:**
- [ ] Define a typed `AuditEvent` struct covering `auth.*` events from the README.
- [ ] Implement an async publisher to `AUDIT_TOPIC` with at-least-once semantics and a local fallback queue.
- [ ] Emit events for login, logout, refresh, MFA enroll/verify, key use/rotate, authz deny, lockout.
- [ ] Ensure no plaintext secrets appear in event payloads.
- [ ] Add correlation via `request_id` and `sid`/`sub` where applicable.

**Acceptance criteria:**
- Every README-listed auth event type is emitted at the corresponding code path.
- Event payload schema matches the contract expected by `audit-event-log`.
- No secret material (passwords, TOTP secrets, full keys, refresh tokens) appears in events.
- Events carry `request_id` for traceability.

## Stage 9: Observability

**Goal:** Add structured logging, metrics, tracing, and health endpoints meeting
the non-functional requirements.

**Tasks:**
- [ ] Add structured JSON logger respecting `LOG_LEVEL` with `request_id` injection.
- [ ] Add Prometheus metrics: login latency histogram, authz decisions, lockouts, MFA challenges, key rotations.
- [ ] Add OpenTelemetry tracing spans for HTTP handlers, DB queries, Redis ops.
- [ ] Add `/healthz` (liveness) and `/readyz` (Postgres + Redis checks) endpoints.
- [ ] Add p99 latency alerting baselines for login and `/v1/authz`.

**Acceptance criteria:**
- Logs are JSON, correlated by `request_id`, no secrets logged.
- Prometheus exposes metrics on `/metrics`.
- Traces propagate through HTTP → DB → Redis.
- `/healthz` and `/readyz` behave correctly during dependency outages.

## Stage 10: Tests, Coverage & CI/Docker Hardening

**Goal:** Reach high test coverage, race-clean suite, and harden Docker + CI per
the README local development and CI guidance.

**Tasks:**
- [ ] Add unit tests for hashers, JWT signer/verifier, TOTP, key generator, RBAC evaluator.
- [ ] Add integration tests with real Postgres + Redis (testcontainers or CI services).
- [ ] Add API-level tests for every endpoint including error envelope shape.
- [ ] Wire `go test ./... -race -cover` and `golangci-lint run` into CI.
- [ ] Upload coverage to Codecov from the existing CI workflow.
- [ ] Harden `Dockerfile` (multi-stage, non-root user, distroless/static or scratch).
- [ ] Pin base image digests and add `dependabot` for Go modules.
- [ ] Add `make migrate-up` / `gen-rbac-bundle` targets and CI smoke job.

**Acceptance criteria:**
- `go test ./... -race -cover` passes with coverage ≥ 80%.
- `golangci-lint run` is clean.
- CI uploads coverage and the Codecov badge updates.
- Docker image runs as non-root and starts in < 2 s.
- `make` targets cover build, test, lint, migrate, gen-bundle.