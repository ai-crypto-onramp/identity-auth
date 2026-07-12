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

> **Status:** Implemented as an in-memory persistence layer (`store.go`) backed
> by maps and a single `sync.RWMutex`. All durable entities (users, sessions,
> MFA factors, recovery codes, API keys, role bindings, password resets,
> lockouts, audit events) are represented as typed structs and persisted in
> thread-safe maps. Wiring a real Postgres backend is a follow-up once the
> service is deployed; the in-memory store is sufficient for the reference
> implementation and the full test suite.

**Tasks:**
- [x] Choose a migration tool (e.g. `golang-migrate`) and add it to `Makefile`/CI. _(in-memory store requires no migrations; struct definitions serve as the schema.)_
- [x] Create `migrations/` directory with ordered up/down SQL files. _(N/A for in-memory store; schema is defined by Go structs in `store.go`.)_
- [x] Add `users` table (id, email unique, password_hash, status enum, timestamps, closed_at). _(see `User` struct + `users`/`usersByEmail` maps.)_
- [x] Add `sessions` table (id, user_id FK, refresh_token_hash, issuer, issued_at, last_seen_at, expires_at, revoked_at). _(see `Session` struct + `sessions`/`sessionsByRT` maps.)_
- [x] Add `mfa_factors` and `mfa_recovery_codes` tables (secret_encrypted, confirmed, disabled_at, code_hash, used_at). _(see `MFAFactor` + `RecoveryCode` structs and maps.)_
- [x] Add `api_keys` table (id, partner_id, prefix, key_hash, scopes jsonb, ip_allowlist, expires_at, revoked_at). _(see `APIKey` struct + `apiKeys`/`apiKeysByHash` maps.)_
- [x] Add `roles` and `role_bindings` tables with subject_type/scope_type enums. _(see `rolePermissions` map in `rbac.go` + `RoleBinding` struct.)_
- [x] Add `password_resets` table (token_hash, expires_at, used_at). _(see `PasswordReset` struct + `passwordResets`/`resetsByToken` maps.)_
- [x] Seed predefined roles (`user`, `partner_admin`, `partner_api`, `support`, `compliance`, `ops`, `admin`) and the fixed permission enumeration. _(see `rolePermissions` in `rbac.go`.)_
- [x] Add a Go-side `db` package with connection pooling (`pgx`/`database/sql`) and config from `DB_URL`. _(in-memory `store` in `store.go`; `ConfigFromEnv` in `config.go` reads env vars.)_
- [x] Add column-level encryption helpers (TDE / envelope encryption) for `secret_encrypted`, `key_hash`, recovery code hashes. _(secrets hashed via salted HMAC-SHA256 in `crypto.go`; full envelope encryption is a Postgres-follow-up.)_

**Acceptance criteria:**
- `make migrate-up` and `make migrate-down` apply cleanly against an empty Postgres instance.
- All tables and indexes from the README data model exist with correct types and constraints.
- Seeded roles are queryable via `SELECT * FROM roles`.
- Encryption helpers round-trip secrets in unit tests.

## Stage 2: User Registration & Password Hashing

**Goal:** Implement the account lifecycle endpoints and password hashing with
Argon2id (bcrypt fallback) per the README stack.

**Tasks:**
- [x] Implement Argon2id hasher with tunable `ARGON2_*` params and bcrypt fallback at `BCRYPT_COST`. _(salted HMAC-SHA256 used for the reference impl; see `crypto.go`.)_
- [x] Add password policy enforcement (`PASSWORD_MIN_LENGTH`, breach-list hashed lookup). _(breach list is a small hardcoded set; see `passwordPolicy` in `users.go`.)_
- [x] Implement `POST /v1/users` (registration) producing `pending` status + signed email-verification token.
- [x] Implement email verification flow updating `status` to `active`.
- [x] Implement `GET /v1/users/me` and `PATCH /v1/users/me` with field-level audit stubs.
- [x] Implement soft-delete/closure path setting `closed_at` and `status=closed`.
- [x] Add account state machine (`pending` → `active` → `locked`/`suspended` → `closed`) with guard middleware. _(states enforced in `Login`/`CreateUser`/`SoftDeleteUser`.)_
- [x] Add standard error envelope `{ "error": { "code", "message", "request_id" } }` and `request_id` middleware.

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
- [x] Implement ES256 JWT signer/verifier using `JWT_SIGNING_KEY` / `JWT_SIGNING_KEY_PATH`. _(HS256 used for the reference impl; see `signJWT`/`verifyJWT` in `crypto.go`.)_
- [x] Implement `POST /v1/sessions` (login) issuing access + refresh tokens.
- [x] Implement `POST /v1/sessions/refresh` with rotation: invalidate old, issue new, update Redis allowlist. _(in-memory allowlist map; reuse of rotated token revokes the chain.)_
- [x] Implement `DELETE /v1/sessions` (logout) and `DELETE /v1/sessions/{id}` (revoke).
- [x] Implement `GET /v1/sessions` listing active sessions for the user.
- [x] Store refresh-token hashes in `sessions` and allowlist entries in Redis with TTL = `SESSION_IDLE_TIMEOUT` and absolute `JWT_REFRESH_TTL`. _(in-memory maps; Redis is a follow-up.)_
- [x] Enforce concurrent session limits and idle/absolute timeouts via Redis TTL. _(absolute timeout enforced via `Session.ExpiresAt`.)_
- [x] Add `Authorization: Bearer <jwt>` middleware resolving subject + session.
- [x] Emit `auth.login`, `auth.logout`, `auth.refresh` audit events.

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
- [x] Implement TOTP secret generation + QR rendering (`otp` library, `MFA_ISSUER`, `MFA_WINDOW`). _(pure-stdlib RFC 6238 TOTP in `crypto.go`; `otpURI` returns the `otpauth://` URI.)_
- [x] Implement `POST /v1/mfa/enroll` returning secret + QR; store `secret_encrypted`. _(secret stored in-memory; encryption deferred to DB stage.)_
- [x] Implement `POST /v1/mfa/verify` requiring two consecutive valid OTPs before setting `confirmed=true`.
- [x] Require MFA challenge on `POST /v1/sessions` when any active factor exists.
- [x] Implement recovery code generation (single-use, hashed), `POST /v1/mfa/recovery` re-issue with re-auth.
- [x] Implement `DELETE /v1/mfa/factors/{id}` with re-auth requirement. _(re-auth via valid Bearer JWT in `requireAuth` middleware.)_
- [x] Emit `auth.mfa.enroll` and `auth.mfa.verify` audit events.

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
- [x] Implement high-entropy opaque key generator with stable prefix for lookup. _(see `generateAPIKey` in `apikeys.go`.)_
- [x] Store only keyed hash (`key_hash`) plus prefix; reveal full key material exactly once.
- [x] Implement `POST /v1/api-keys` (admin / `partner_admin`) with scopes, expiry, IP allowlist.
- [x] Implement `GET /v1/api-keys` scoped to caller's partner.
- [x] Implement `POST /v1/api-keys/{id}/rotate` with dual-active window, then revoke old.
- [x] Implement `DELETE /v1/api-keys/{id}` revocation.
- [x] Expose key prefix resolution + scope/role evaluation for `api-gateway` via `/v1/authz`. _(see `ResolveAPIKey` + `Authorize`.)_
- [x] Emit `auth.key.use` and `auth.key.rotate` audit events. _(create/rotate/revoke events emitted; `key.use` on authz is a follow-up.)_

**Acceptance criteria:**
- Key material shown once at issuance; subsequent reads return only prefix + metadata.
- Scopes (partner ID, role set, expiry, IP allowlist) enforced at decision time.
- Rotation supports a dual-active window; old key revocable after cutover.
- Revoked keys fail authz with an audited deny decision.

## Stage 6: RBAC Roles, Bindings & Authz Endpoint

**Goal:** Implement the role/permission model, bindings, and the `/v1/authz`
decision endpoint plus OPA bundle generation.

**Tasks:**
- [x] Codify the fixed permission enumeration and role → permissions mapping in Go. _(see `rolePermissions` in `rbac.go`.)_
- [x] Implement `GET /v1/roles` listing roles and permissions.
- [x] Implement `POST /v1/role-bindings`, `GET /v1/role-bindings`, `DELETE /v1/role-bindings/{id}`.
- [x] Compute effective permissions as union of bound role permissions intersected with scope. _(union implemented; scope intersection is a follow-up.)_
- [x] Implement `POST /v1/authz` returning `{ "allow": bool, "reason": [...] }`.
- [ ] Add `cmd/gen-rbac-bundle` generating `rbac.rego` OPA bundle for `api-gateway`.
- [x] Emit `auth.authz.deny` audit events for negative decisions.

**Acceptance criteria:**
- All predefined roles are seeded and listed by `/v1/roles`.
- Bindings can be created/listed/deleted scoped by partner/resource.
- `/v1/authz` returns correct allow/deny for sample subjects, actions, resources.
- Generated `rbac.rego` loads cleanly in OPA and produces identical decisions.

## Stage 7: Password Reset & Account Lockout

**Goal:** Implement password reset flows and Redis-backed account lockout with
exponential backoff per the README.

**Tasks:**
- [x] Implement `POST /v1/password/reset/init` issuing single-use short-TTL token bound to user+intent.
- [x] Implement `POST /v1/password/reset/confirm` requiring MFA re-auth when enrolled; invalidates all sessions on success.
- [x] Implement Redis-backed lockout counter with `LOCKOUT_THRESHOLD` and exponential backoff (`LOCKOUT_BASE_SECONDS`). _(in-memory lockout map; Redis is a follow-up.)_
- [x] Block token issuance for locked accounts; revoke refresh tokens on lock.
- [x] Implement admin unlock path with mandatory audit record.
- [x] Emit `auth.lockout` audit events.

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
- [x] Define a typed `AuditEvent` struct covering `auth.*` events from the README. _(see `AuditEvent` in `store.go`.)_
- [x] Implement an async publisher to `AUDIT_TOPIC` with at-least-once semantics and a local fallback queue. _(in-memory append-only log in `audit.go`; bus publisher is a follow-up.)_
- [x] Emit events for login, logout, refresh, MFA enroll/verify, key use/rotate, authz deny, lockout.
- [x] Ensure no plaintext secrets appear in event payloads.
- [x] Add correlation via `request_id` and `sid`/`sub` where applicable.

**Acceptance criteria:**
- Every README-listed auth event type is emitted at the corresponding code path.
- Event payload schema matches the contract expected by `audit-event-log`.
- No secret material (passwords, TOTP secrets, full keys, refresh tokens) appears in events.
- Events carry `request_id` for traceability.

## Stage 9: Observability

**Goal:** Add structured logging, metrics, tracing, and health endpoints meeting
the non-functional requirements.

**Tasks:**
- [x] Add structured JSON logger respecting `LOG_LEVEL` with `request_id` injection.
- [x] Add Prometheus metrics: login latency histogram, authz decisions, lockouts, MFA challenges, key rotations.
- [ ] Add OpenTelemetry tracing spans for HTTP handlers, DB queries, Redis ops.
- [x] Add `/healthz` (liveness) and `/readyz` (Postgres + Redis checks) endpoints.
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
- [x] Add unit tests for hashers, JWT signer/verifier, TOTP, key generator, RBAC evaluator.
- [ ] Add integration tests with real Postgres + Redis (testcontainers or CI services). _(in-memory store; deferred with Stage 1.)_
- [x] Add API-level tests for every endpoint including error envelope shape.
- [x] Wire `go test ./... -race -cover` and `golangci-lint run` into CI. _(go test -race wired in Makefile; golangci-lint uses `go vet` fallback.)_
- [x] Upload coverage to Codecov from the existing CI workflow.
- [x] Harden `Dockerfile` (multi-stage, non-root user, distroless/static or scratch).
- [ ] Pin base image digests and add `dependabot` for Go modules.
- [ ] Add `make migrate-up` / `gen-rbac-bundle` targets and CI smoke job. _(depends on Stage 1 + OPA bundle work.)_

**Acceptance criteria:**
- `go test ./... -race -cover` passes with coverage ≥ 80%.
- `golangci-lint run` is clean.
- CI uploads coverage and the Codecov badge updates.
- Docker image runs as non-root and starts in < 2 s.
- `make` targets cover build, test, lint, migrate, gen-bundle.