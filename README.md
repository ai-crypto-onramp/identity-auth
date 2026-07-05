# Identity & Auth

User accounts, sessions, MFA, API keys for B2B partners, RBAC for the crypto on-ramp.

## Overview / Responsibilities

- Manage end-user account lifecycle (registration, profile, status, deletion).
- Issue and validate session credentials (access + refresh tokens) consumed by the API Gateway.
- Enforce multi-factor authentication (MFA) via TOTP / OTP factors.
- Issue, rotate, and revoke API keys for B2B partners.
- Provide role-based access control (RBAC) definitions, bindings, and policy decisions.
- Handle password reset flows and account lockout on repeated failures.
- Emit an audit event for every authentication and authorization decision.

## Language & Tech Stack

- **Language:** Go
- **HTTP router:** `chi` (or `echo`) — idiomatic, net/http-compatible, middleware-friendly.
- **Persistence:** PostgreSQL (users, factors, API keys, roles, bindings).
- **Session store:** Redis (refresh-token allowlist, session revocation, lockout counters).
- **Password hashing:** Argon2id (preferred); bcrypt fallback with tunable cost.
- **MFA:** TOTP (RFC 6238) via OTP, with recovery codes.
- **Tokens:** JWT access tokens (short TTL, signed ES256); opaque refresh tokens rotated on use.
- **RBAC:** Role/permission model enforced via OPA sidecar / bundle policies.

## System Requirements

### User Account Lifecycle

- Create accounts with unique email / partner-scoped identifier.
- Verify email ownership via signed token link.
- Support account states: `pending`, `active`, `locked`, `suspended`, `closed`.
- Soft-delete on closure; retain minimal audit stub per compliance retention.
- Allow profile updates (name, locale, contact) with field-level audit.

### Session Management

- Login with email + password (and MFA when enrolled).
- Issue short-lived JWT access token and long-lived opaque refresh token.
- Rotate refresh token on every use; revoke on logout / suspicion.
- Support concurrent session limits and per-user session listing / revocation.
- Idle and absolute timeout enforced server-side via Redis TTL.

### MFA Enrollment & Verification

- Enroll TOTP factor: generate secret, render QR, store hashed secret.
- Verify enrollment with two consecutive valid OTPs before activation.
- Require MFA challenge on login when any factor is active.
- Provide recovery codes (single-use, hashed) and re-issue flow.
- Support per-factor disable with re-auth requirement.

### Partner API Key Issuance & Rotation

- B2B partners request API keys via authenticated endpoint.
- Keys are opaque, high-entropy, stored only as keyed hash (lookup via prefix).
- Support scoped keys: partner ID, role set, expiry, IP allowlist.
- Rotation: issue replacement, dual-active window, revoke old key.
- Reveal full key material exactly once at issuance.

### RBAC Roles & Permissions

- Predefined roles: `user`, `partner_admin`, `partner_api`, `support`, `compliance`, `ops`, `admin`.
- Permissions are granular (e.g., `tx:read`, `tx:create`, `kyc:read`, `keys:rotate`).
- Bindings associate a subject (user or API key) with a role, optionally scoped to a partner or resource.
- Policy decisions exposed to the API Gateway via `/v1/authz` (or OPA bundle).

### Password Reset

- Initiate reset via email; token single-use, short TTL, bound to user + intent.
- Reset requires re-auth of any active MFA factor when enrolled.
- Invalidate all active sessions on successful password change.
- Enforce password policy (min length, breach-list check via hashed lookup).

### Account Lockout

- Lockout after N consecutive failed authentications (configurable, default 5).
- Exponential backoff on repeated failures; Redis-backed counter.
- Admin unlock path with mandatory audit record.
- Locked accounts cannot issue new tokens; refresh tokens revoked.

## Non-Functional Requirements

- Authentication p99 latency < 30 ms (excluding MFA OTP user input).
- 99.99% availability for login, token validation, and authz decisions.
- All secrets at rest encrypted (DB TDE / column-level for keys, factors, recovery codes).
- All secrets in transit over TLS 1.2+; no plaintext secrets logged.
- Every auth event (login, logout, token refresh, MFA, key use, authz deny) emitted to audit-event-log.
- Horizontal scalability; stateless API except Redis-cached session/lockout state.

## Technical Specifications

### API Surface

REST over HTTPS. JSON request/response. Standard error envelope `{ "error": { "code", "message", "request_id" } }`. All endpoints require correlation `request_id` header; auth endpoints require `Authorization: Bearer <jwt>` except login/refresh/reset.

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/v1/users` | Register a new user account. |
| GET | `/v1/users/me` | Get the authenticated user's profile. |
| PATCH | `/v1/users/me` | Update profile fields. |
| POST | `/v1/sessions` | Login (email + password, optional MFA challenge). |
| DELETE | `/v1/sessions` | Logout / revoke current session. |
| POST | `/v1/sessions/refresh` | Exchange refresh token for new access token. |
| GET | `/v1/sessions` | List active sessions for the user. |
| DELETE | `/v1/sessions/{id}` | Revoke a specific session. |
| POST | `/v1/mfa/enroll` | Begin TOTP enrollment; returns secret + QR. |
| POST | `/v1/mfa/verify` | Verify enrollment OTP(s) and activate factor. |
| DELETE | `/v1/mfa/factors/{id}` | Disable an MFA factor (re-auth required). |
| POST | `/v1/mfa/recovery` | Re-issue recovery codes (re-auth required). |
| POST | `/v1/password/reset/init` | Send password reset email. |
| POST | `/v1/password/reset/confirm` | Confirm reset with token + new password. |
| POST | `/v1/api-keys` | Issue a partner API key (admin / partner_admin). |
| GET | `/v1/api-keys` | List API keys for the caller's partner scope. |
| POST | `/v1/api-keys/{id}/rotate` | Rotate an API key. |
| DELETE | `/v1/api-keys/{id}` | Revoke an API key. |
| GET | `/v1/roles` | List available roles and permissions. |
| POST | `/v1/role-bindings` | Bind a subject to a role. |
| GET | `/v1/role-bindings` | List role bindings (scoped). |
| DELETE | `/v1/role-bindings/{id}` | Remove a role binding. |
| POST | `/v1/authz` | Evaluate a permission decision for a subject + action + resource. |

### Data Model

- `users` — `id`, `email` (unique), `password_hash`, `status`, `created_at`, `updated_at`, `closed_at`.
- `sessions` — `id`, `user_id`, `refresh_token_hash`, `issuer`, `issued_at`, `last_seen_at`, `expires_at`, `revoked_at`.
- `mfa_factors` — `id`, `user_id`, `type` (`totp`), `secret_encrypted`, `confirmed`, `created_at`, `disabled_at`.
- `mfa_recovery_codes` — `id`, `user_id`, `code_hash`, `used_at`.
- `api_keys` — `id`, `partner_id`, `prefix`, `key_hash`, `scopes`, `ip_allowlist`, `expires_at`, `created_at`, `revoked_at`.
- `roles` — `id`, `name`, `permissions` (array), `description`.
- `role_bindings` — `id`, `subject_type` (`user` / `api_key`), `subject_id`, `role_id`, `scope_type`, `scope_id`, `created_at`.
- `password_resets` — `id`, `user_id`, `token_hash`, `expires_at`, `used_at`.
- `lockouts` — `user_id`, `fail_count`, `locked_until`, `updated_at` (Redis-backed).

### Integrations

- **Consumed by:** `api-gateway` (token validation, `/v1/authz` decisions, partner key auth).
- **Emits to:** `audit-event-log` (event bus) — `auth.login`, `auth.logout`, `auth.refresh`, `auth.mfa.enroll`, `auth.mfa.verify`, `auth.key.use`, `auth.key.rotate`, `auth.authz.deny`, `auth.lockout`.
- **Reads from:** none at runtime; onboarding status synced from `onboarding-kyc` via out-of-band webhook for `users.status` enrichment.

### Auth

- **Access token:** JWT, ES256 signed, `JWT_ACCESS_TTL` (default 15m), claims include `sub`, `sid`, `scope`, `roles`, `exp`, `iat`, `iss`.
- **Refresh token:** opaque, high-entropy, stored hashed in `sessions` + allowlisted in Redis; rotated on every refresh; revocable.
- **Partner API key auth:** `api-gateway` resolves key prefix → `identity-auth` `/v1/authz` for scope/role evaluation.
- **Service-to-service:** mTLS in cluster; no shared long-lived service tokens.

### RBAC

- Roles defined in code + seeded in `roles` table; permissions are a fixed enumeration.
- Bindings stored in `role_bindings`; effective permissions = union of bound role permissions, intersected with scope.
- OPA bundle (`rbac.rego`) generated from role/permission model and distributed to `api-gateway` for local policy decisions; `identity-auth` remains source of truth.
- `/v1/authz` returns `{ "allow": bool, "reason": [...] }` for fallback / cold-path evaluation.

## Dependencies

- **PostgreSQL** — durable store for users, factors, keys, roles, bindings.
- **Redis** — refresh-token allowlist, session metadata, lockout counters, rate-limit windows.
- **audit-event-log** — async consumer of all auth events via the event bus.
- **(Optional) OPA** — bundle distribution server for RBAC policy.

## Configuration

| Env Var | Required | Default | Description |
|---|---|---|---|
| `PORT` | yes | `8080` | HTTP listen port. |
| `DB_URL` | yes | — | PostgreSQL DSN (`postgres://...`). |
| `REDIS_URL` | yes | — | Redis address (`redis://...`). |
| `JWT_ISSUER` | yes | `identity-auth` | `iss` claim and validation expected value. |
| `JWT_ACCESS_TTL` | no | `15m` | Access token lifetime. |
| `JWT_REFRESH_TTL` | no | `720h` (30d) | Refresh token absolute lifetime. |
| `JWT_SIGNING_KEY` | yes | — | ES256 private key (PEM or path via `JWT_SIGNING_KEY_PATH`). |
| `MFA_ISSUER` | yes | — | TOTP issuer label shown in authenticator apps. |
| `MFA_WINDOW` | no | `1` | TOTP ±window steps allowed. |
| `BCRYPT_COST` | no | `12` | bcrypt cost when bcrypt fallback is used. |
| `ARGON2_MEMORY_KIB` | no | `65536` | Argon2id memory parameter. |
| `ARGON2_ITERATIONS` | no | `3` | Argon2id time cost. |
| `ARGON2_PARALLELISM` | no | `2` | Argon2id parallelism. |
| `LOCKOUT_THRESHOLD` | no | `5` | Failed attempts before lockout. |
| `LOCKOUT_BASE_SECONDS` | no | `30` | Initial lockout duration; exponential backoff multiplier. |
| `SESSION_IDLE_TIMEOUT` | no | `24h` | Redis session TTL (sliding). |
| `PASSWORD_MIN_LENGTH` | no | `12` | Minimum password length. |
| `AUDIT_TOPIC` | yes | `auth.events` | Event bus topic for audit events. |
| `LOG_LEVEL` | no | `info` | One of `debug`, `info`, `warn`, `error`. |

## Local Development

```sh
# Build
go build ./...

# Run (requires PostgreSQL + Redis reachable)
go run ./cmd/identity-auth

# Test
go test ./... -race -cover

# Lint / vet
go vet ./...
golangci-lint run

# Generate OPA bundle
go run ./cmd/gen-rbac-bundle --out ./bundle/
```