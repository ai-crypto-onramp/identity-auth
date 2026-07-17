package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ai-crypto-onramp/identity-auth/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// DB-backed store implementation. *dbstore.Store implements the Store
// interface using a *pgxpool.Pool against the schema in
// db/migrations/*.sql. Sensitive MFA secrets are encrypted at rest with
// db.Encryptor (AES-256-GCM).
// ---------------------------------------------------------------------------

// dbDSN returns the configured Postgres DSN (DB_URL env var).
func dbDSN() string { return dbDSNFromEnv() }

func dbDSNFromEnv() string {
	return db.DefaultConfig().DSN
}

// openPool opens a pgx connection pool for the given DSN.
func openPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg := db.DefaultConfig()
	cfg.DSN = dsn
	return db.Pool(ctx, cfg)
}

// migrateUp applies pending migrations.
func migrateUp(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	return db.MigrateUp(ctx, pool)
}

// newDBStore builds a DB-backed store from an open pool.
func newDBStore(pool *pgxpool.Pool) (*dbstore, error) {
	enc, err := db.NewEncryptorFromEnv()
	if err != nil {
		return nil, fmt.Errorf("init encryptor: %w", err)
	}
	return &dbstore{pool: pool, enc: enc}, nil
}

// dbstore is the PostgreSQL-backed Store implementation.
type dbstore struct {
	pool *pgxpool.Pool
	enc  *db.Encryptor
}

// compile-time assertion that *dbstore implements Store.
var _ Store = (*dbstore)(nil)

// ---------------------------------------------------------------------------
// Users.
// ---------------------------------------------------------------------------

func (s *dbstore) CreateUser(email, password string) (*User, string, error) {
	email = normalizeEmail(email)
	if email == "" {
		return nil, "", ErrBadRequest
	}
	if err := passwordPolicy(password); err != nil {
		return nil, "", err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, "", err
	}
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	now := time.Now()
	id := randID()
	if _, err := tx.Exec(ctx,
		"INSERT INTO users(id, email, password_hash, status, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$5)",
		id, email, hash, string(StatusPending), now); err != nil {
		return nil, "", ErrEmailTaken
	}
	token := randomToken(24)
	if _, err := tx.Exec(ctx,
		"INSERT INTO verification_tokens(token_hash, user_id, created_at) VALUES($1,$2,$3)",
		sha256Hex(token), id, now); err != nil {
		return nil, "", fmt.Errorf("insert verification token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &User{ID: id, Email: email, PasswordHash: hash, Status: StatusPending, CreatedAt: now, UpdatedAt: now}, token, nil
}

func (s *dbstore) VerifyUserToken(token string) (*User, error) {
	ctx := context.Background()
	hash := sha256Hex(token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var uid string
	err = tx.QueryRow(ctx, "DELETE FROM verification_tokens WHERE token_hash=$1 RETURNING user_id", hash).Scan(&uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	tag, err := tx.Exec(ctx,
		"UPDATE users SET status='ACTIVE', updated_at=now() WHERE id=$1 AND status='PENDING'", uid)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrInvalidToken
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.UserByID(uid), nil
}

func (s *dbstore) VerifyUser(uid string) error {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx,
		"UPDATE users SET status='ACTIVE', updated_at=now() WHERE id=$1 AND status='PENDING'", uid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either user doesn't exist or isn't pending.
		if u := s.UserByID(uid); u == nil {
			return ErrUserNotFound
		}
		return ErrInvalidToken
	}
	return nil
}

func (s *dbstore) UserByID(id string) *User {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx,
		"SELECT id, email, password_hash, status, created_at, updated_at, closed_at FROM users WHERE id=$1", id)
	u, err := scanUser(row)
	if err != nil {
		return nil
	}
	return u
}

func (s *dbstore) UserByEmail(email string) *User {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx,
		"SELECT id, email, password_hash, status, created_at, updated_at, closed_at FROM users WHERE email=$1",
		normalizeEmail(email))
	u, err := scanUser(row)
	if err != nil {
		return nil
	}
	return u
}

func (s *dbstore) UpdateUserEmail(id, email string) (*User, error) {
	email = normalizeEmail(email)
	if email == "" {
		return nil, ErrBadRequest
	}
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var status string
	err = tx.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", id).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if status == string(StatusClosed) {
		return nil, ErrAccountClosed
	}
	tag, err := tx.Exec(ctx, "UPDATE users SET email=$1, updated_at=now() WHERE id=$2", email, id)
	if err != nil {
		// Unique violation → email taken.
		return nil, ErrEmailTaken
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrUserNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.UserByID(id), nil
}

func (s *dbstore) SoftDeleteUser(id string) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx,
		"UPDATE users SET status='CLOSED', updated_at=now(), closed_at=now() WHERE id=$1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(ctx,
		"UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *dbstore) SetUserPassword(id, password string) error {
	if err := passwordPolicy(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx,
		"UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2", hash, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *dbstore) RevokeAllSessionsForUser(userID string) {
	ctx := context.Background()
	_, _ = s.pool.Exec(ctx,
		"UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", userID)
}

// ---------------------------------------------------------------------------
// Sessions + lockouts.
// ---------------------------------------------------------------------------

func (s *dbstore) Login(email, password, mfaCode string, cfg *Config) (*LoginResult, *AuditEvent, error) {
	ctx := context.Background()
	end := observeDBSpan(ctx, "users.getByEmail")
	u := s.UserByEmail(email)
	end(nil)
	if u == nil {
		return nil, nil, ErrInvalidCredentials
	}
	if u.Status == StatusClosed {
		return nil, nil, ErrAccountClosed
	}
	if u.Status == StatusPending {
		return nil, nil, ErrAccountPending
	}
	end = observeDBSpan(ctx, "lockouts.check")
	locked := s.isLocked(u.ID)
	end(nil)
	if locked {
		return nil, nil, ErrAccountLocked
	}
	if !verifyPassword(u.PasswordHash, password) {
		end = observeDBSpan(ctx, "lockouts.recordFailure")
		s.recordFailure(u.ID)
		end(nil)
		if s.isLocked(u.ID) {
			return nil, nil, ErrAccountLocked
		}
		return nil, nil, ErrInvalidCredentials
	}
	factors := s.confirmedFactors(u.ID)
	if len(factors) > 0 {
		if mfaCode == "" {
			return nil, nil, ErrMFARequired
		}
		if !s.validateMFA(u.ID, mfaCode) {
			s.recordFailure(u.ID)
			return nil, nil, ErrMFAInvalid
		}
	}
	s.resetLockout(u.ID)
	return s.issueSession(u.ID, cfg)
}

func (s *dbstore) issueSession(userID string, cfg *Config) (*LoginResult, *AuditEvent, error) {
	ctx := context.Background()
	sid := randID()
	refresh := randomToken(32)
	refreshHash := sha256Hex(refresh)
	now := time.Now()
	end := observeDBSpan(ctx, "sessions.insert")
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions(id, user_id, refresh_token_hash, issuer, issued_at, last_seen_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$5,$6)`,
		sid, userID, refreshHash, cfg.JWTIssuer, now, now.Add(SessionTTL))
	end(err)
	if err != nil {
		return nil, nil, err
	}
	end = observeRedisSpan(ctx, "SET refresh_allowlist")
	end(nil)

	claims := JWTClaims{
		Sub: userID,
		Sid: sid,
		Iat: now.Unix(),
		Exp: now.Add(AccessTokenTTL).Unix(),
		Iss: cfg.JWTIssuer,
	}
	access, err := signJWT(claims, cfg.JWTSecret)
	if err != nil {
		return nil, nil, err
	}
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.login",
		SubjectID: userID,
		SessionID: sid,
		Metadata:  map[string]any{},
		CreatedAt: now,
	}
	return &LoginResult{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(AccessTokenTTL.Seconds())}, &ev, nil
}

func (s *dbstore) Refresh(refreshToken string, cfg *Config) (*LoginResult, *AuditEvent, error) {
	ctx := context.Background()
	hash := sha256Hex(refreshToken)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var (
		sid        string
		userID     string
		revokedAt  *time.Time
		expiresAt  time.Time
	)
	err = tx.QueryRow(ctx,
		"SELECT id, user_id, revoked_at, expires_at FROM sessions WHERE refresh_token_hash=$1 FOR UPDATE",
		hash).Scan(&sid, &userID, &revokedAt, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Reuse detection: check if token was already rotated.
			var prevSID string
			err2 := tx.QueryRow(ctx, "SELECT session_id FROM used_refresh_tokens WHERE token_hash=$1", hash).Scan(&prevSID)
			if err2 == nil {
				_ = tx.Commit(ctx)
				_ = s.RevokeSession(prevSID)
				return nil, nil, ErrRefreshTokenInvalid
			}
			return nil, nil, ErrRefreshTokenInvalid
		}
		return nil, nil, err
	}
	if revokedAt != nil {
		return nil, nil, ErrRefreshTokenInvalid
	}
	if time.Now().After(expiresAt) {
		return nil, nil, ErrRefreshTokenInvalid
	}
	newRT := randomToken(32)
	newHash := sha256Hex(newRT)
	if _, err := tx.Exec(ctx,
		"UPDATE sessions SET refresh_token_hash=$1, last_seen_at=now() WHERE id=$2", newHash, sid); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO used_refresh_tokens(token_hash, session_id) VALUES($1,$2)", hash, sid); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	claims := JWTClaims{
		Sub: userID,
		Sid: sid,
		Iat: now.Unix(),
		Exp: now.Add(AccessTokenTTL).Unix(),
		Iss: cfg.JWTIssuer,
	}
	access, err := signJWT(claims, cfg.JWTSecret)
	if err != nil {
		return nil, nil, err
	}
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.refresh",
		SubjectID: userID,
		SessionID: sid,
		Metadata:  map[string]any{},
		CreatedAt: now,
	}
	return &LoginResult{AccessToken: access, RefreshToken: newRT, ExpiresIn: int64(AccessTokenTTL.Seconds())}, &ev, nil
}

func (s *dbstore) Logout(sessionID string) (*AuditEvent, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var userID string
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, "SELECT user_id, revoked_at FROM sessions WHERE id=$1", sessionID).Scan(&userID, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	if revokedAt != nil {
		_ = tx.Commit(ctx)
		return nil, nil
	}
	now := time.Now()
	if _, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at=$1 WHERE id=$2", now, sessionID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AuditEvent{
		ID: randID(), Type: "auth.logout", SubjectID: userID, SessionID: sessionID,
		Metadata: map[string]any{}, CreatedAt: now,
	}, nil
}

func (s *dbstore) RevokeSession(sessionID string) error {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx,
		"UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL", sessionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either doesn't exist or already revoked.
		var exists bool
		err = s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1)", sessionID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrSessionNotFound
		}
	}
	return nil
}

func (s *dbstore) ListSessions(userID string) []*Session {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, refresh_token_hash, issuer, issued_at, last_seen_at, expires_at, revoked_at
		 FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]*Session, 0)
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil
		}
		out = append(out, sess)
	}
	return out
}

func (s *dbstore) SessionByID(sid string) (*Session, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, refresh_token_hash, issuer, issued_at, last_seen_at, expires_at, revoked_at
		 FROM sessions WHERE id=$1`, sid)
	sess, err := scanSession(row)
	if err != nil || sess == nil || sess.RevokedAt != nil {
		return nil, false
	}
	return sess, true
}

func (s *dbstore) UnlockUser(userID string) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)", userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(ctx, "DELETE FROM lockouts WHERE user_id=$1", userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *dbstore) recordFailure(userID string) {
	ctx := context.Background()
	_, _ = s.pool.Exec(ctx,
		`INSERT INTO lockouts(user_id, fail_count, updated_at) VALUES($1,1,now())
		 ON CONFLICT(user_id) DO UPDATE SET fail_count=lockouts.fail_count+1, updated_at=now()`, userID)
	// Apply lockout if threshold reached.
	now := time.Now()
	var failCount int
	_ = s.pool.QueryRow(ctx, "SELECT fail_count FROM lockouts WHERE user_id=$1", userID).Scan(&failCount)
	if failCount >= LockoutThreshold {
		dur := time.Duration(LockoutBaseSeconds) * time.Second
		dur = dur << uint(failCount-LockoutThreshold)
		if dur > 24*time.Hour {
			dur = 24 * time.Hour
		}
		until := now.Add(dur)
		_, _ = s.pool.Exec(ctx, "UPDATE lockouts SET locked_until=$1 WHERE user_id=$2", until, userID)
	}
}

func (s *dbstore) isLocked(userID string) bool {
	ctx := context.Background()
	var until *time.Time
	_ = s.pool.QueryRow(ctx, "SELECT locked_until FROM lockouts WHERE user_id=$1", userID).Scan(&until)
	if until == nil {
		return false
	}
	return time.Now().Before(*until)
}

func (s *dbstore) resetLockout(userID string) {
	ctx := context.Background()
	_, _ = s.pool.Exec(ctx, "DELETE FROM lockouts WHERE user_id=$1", userID)
}

// ---------------------------------------------------------------------------
// MFA.
// ---------------------------------------------------------------------------

func (s *dbstore) EnrollMFA(userID string, cfg *Config) (*MFAEnrollResult, *AuditEvent, error) {
	ctx := context.Background()
	var status string
	err := s.pool.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", userID).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrUserNotFound
		}
		return nil, nil, err
	}
	if status == string(StatusClosed) {
		return nil, nil, ErrAccountClosed
	}
	secret, err := randomTOTPSecret()
	if err != nil {
		return nil, nil, err
	}
	encSecret, err := s.enc.EncryptString(secret)
	if err != nil {
		return nil, nil, err
	}
	id := randID()
	now := time.Now()
	if _, err := s.pool.Exec(ctx,
		"INSERT INTO mfa_factors(id, user_id, type, secret_encrypted, confirmed, created_at) VALUES($1,$2,'TOTP',$3,false,$4)",
		id, userID, []byte(encSecret), now); err != nil {
		return nil, nil, err
	}
	ev := AuditEvent{
		ID: randID(), Type: "auth.mfa.enroll", SubjectID: userID,
		Metadata: map[string]any{"factor_id": id}, CreatedAt: now,
	}
	u := s.UserByID(userID)
	qr := ""
	if u != nil {
		qr = otpURI(cfg.MFAIssuer, u.Email, secret)
	}
	return &MFAEnrollResult{FactorID: id, Secret: secret, QRURI: qr}, &ev, nil
}

func (s *dbstore) VerifyMFA(userID, code1, code2 string) (*AuditEvent, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx,
		`SELECT id, secret_encrypted FROM mfa_factors
		 WHERE user_id=$1 AND confirmed=false AND disabled_at IS NULL
		 ORDER BY created_at DESC LIMIT 1`, userID)
	var (
		id     string
		encSec []byte
	)
	err := row.Scan(&id, &encSec)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFactorNotConfirmed
		}
		return nil, err
	}
	secret, err := s.enc.DecryptString(string(encSec))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if !totpWindowValid(secret, code1, now, 1) {
		return nil, ErrMFAInvalid
	}
	if code1 == code2 {
		return nil, ErrMFAInvalid
	}
	prev := now.Add(-30 * time.Second)
	next := now.Add(30 * time.Second)
	if !totpWindowValid(secret, code2, prev, 0) && !totpWindowValid(secret, code2, next, 0) {
		return nil, ErrMFAInvalid
	}
	if _, err := s.pool.Exec(ctx, "UPDATE mfa_factors SET confirmed=true WHERE id=$1", id); err != nil {
		return nil, err
	}
	return &AuditEvent{
		ID: randID(), Type: "auth.mfa.verify", SubjectID: userID,
		Metadata: map[string]any{"factor_id": id}, CreatedAt: now,
	}, nil
}

func (s *dbstore) confirmedFactors(userID string) []*MFAFactor {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx,
		"SELECT id, user_id, type, secret_encrypted, confirmed, created_at, disabled_at FROM mfa_factors WHERE user_id=$1 AND confirmed=true AND disabled_at IS NULL",
		userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]*MFAFactor, 0)
	for rows.Next() {
		f, err := scanFactor(rows, s.enc)
		if err != nil {
			return nil
		}
		out = append(out, f)
	}
	return out
}

func (s *dbstore) validateMFA(userID, code string) bool {
	if len(code) == 0 {
		return false
	}
	for _, f := range s.confirmedFactors(userID) {
		if totpWindowValid(f.Secret, code, time.Now(), 1) {
			return true
		}
	}
	// Try recovery codes.
	ctx := context.Background()
	hash := sha256Hex(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx,
		"UPDATE mfa_recovery_codes SET used_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL",
		userID, hash)
	if err != nil {
		return false
	}
	if tag.RowsAffected() == 0 {
		return false
	}
	_ = tx.Commit(ctx)
	return true
}

func (s *dbstore) GenerateRecoveryCodes(userID string) ([]string, *AuditEvent, error) {
	ctx := context.Background()
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)", userID).Scan(&exists); err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, nil, ErrUserNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "DELETE FROM mfa_recovery_codes WHERE user_id=$1", userID); err != nil {
		return nil, nil, err
	}
	codes := make([]string, 0, 10)
	now := time.Now()
	for i := 0; i < 10; i++ {
		c := randomToken(8)
		codes = append(codes, c)
		if _, err := tx.Exec(ctx,
			"INSERT INTO mfa_recovery_codes(id, user_id, code_hash) VALUES($1,$2,$3)",
			randID(), userID, sha256Hex(c)); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	ev := AuditEvent{
		ID: randID(), Type: "auth.mfa.recovery", SubjectID: userID,
		Metadata: map[string]any{"count": len(codes)}, CreatedAt: now,
	}
	return codes, &ev, nil
}

func (s *dbstore) DisableFactor(userID, factorID string) (*AuditEvent, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var fUserID string
	err = tx.QueryRow(ctx, "SELECT user_id FROM mfa_factors WHERE id=$1", factorID).Scan(&fUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFactorNotFound
		}
		return nil, err
	}
	if fUserID != userID {
		return nil, ErrFactorNotFound
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		"UPDATE mfa_factors SET disabled_at=$1, confirmed=false WHERE id=$2", now, factorID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AuditEvent{
		ID: randID(), Type: "auth.mfa.disable", SubjectID: userID,
		Metadata: map[string]any{"factor_id": factorID}, CreatedAt: now,
	}, nil
}

// ---------------------------------------------------------------------------
// API keys.
// ---------------------------------------------------------------------------

func (s *dbstore) CreateAPIKey(partnerID string, scopes, ipAllowlist []string, expiresAt *time.Time) (*APIKeyResult, *AuditEvent, error) {
	if partnerID == "" {
		return nil, nil, ErrBadRequest
	}
	key, prefix, err := generateAPIKey()
	if err != nil {
		return nil, nil, err
	}
	id := randID()
	now := time.Now()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO api_keys(id, partner_id, prefix, key_hash, scopes, ip_allowlist, expires_at, created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, partnerID, prefix, sha256Hex(key),
		jsonScopes(scopes), jsonAllowlist(ipAllowlist), expiresAt, now); err != nil {
		return nil, nil, err
	}
	ev := AuditEvent{
		ID: randID(), Type: "auth.key.create", SubjectID: partnerID,
		Metadata: map[string]any{"key_id": id, "prefix": prefix}, CreatedAt: now,
	}
	return &APIKeyResult{
		ID: id, PartnerID: partnerID, Key: key, Prefix: prefix,
		Scopes: scopes, IPAllowlist: ipAllowlist, ExpiresAt: expiresAt,
	}, &ev, nil
}

func (s *dbstore) ListAPIKeys(partnerID string) []*APIKey {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx,
		`SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist, expires_at, created_at, revoked_at,
		        previous_key_hash, previous_prefix, rotated_at
		 FROM api_keys WHERE partner_id=$1`, partnerID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]*APIKey, 0)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil
		}
		out = append(out, k)
	}
	return out
}

func (s *dbstore) RotateAPIKey(id string) (*APIKeyResult, *AuditEvent, error) {
	key, prefix, err := generateAPIKey()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var (
		partnerID   string
		scopesJSON  []byte
		allowJSON   []byte
		expiresAt   *time.Time
		oldHash     string
		oldPrefix   string
		revokedAt   *time.Time
	)
	err = tx.QueryRow(ctx,
		"SELECT partner_id, scopes, ip_allowlist, expires_at, key_hash, prefix, revoked_at FROM api_keys WHERE id=$1 FOR UPDATE",
		id).Scan(&partnerID, &scopesJSON, &allowJSON, &expiresAt, &oldHash, &oldPrefix, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrAPIKeyNotFound
		}
		return nil, nil, err
	}
	if revokedAt != nil {
		return nil, nil, ErrAPIKeyNotFound
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`UPDATE api_keys SET previous_key_hash=key_hash, previous_prefix=prefix, rotated_at=$1,
		                     key_hash=$2, prefix=$3 WHERE id=$4`,
		now, sha256Hex(key), prefix, id); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	scopes := parseStrings(scopesJSON)
	allow := parseStrings(allowJSON)
	ev := AuditEvent{
		ID: randID(), Type: "auth.key.rotate", SubjectID: partnerID,
		Metadata: map[string]any{"key_id": id, "prefix": prefix}, CreatedAt: now,
	}
	return &APIKeyResult{
		ID: id, PartnerID: partnerID, Key: key, Prefix: prefix,
		Scopes: scopes, IPAllowlist: allow, ExpiresAt: expiresAt,
	}, &ev, nil
}

func (s *dbstore) RevokeAPIKey(id string) (*AuditEvent, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var (
		partnerID string
		revokedAt *time.Time
	)
	err = tx.QueryRow(ctx, "SELECT partner_id, revoked_at FROM api_keys WHERE id=$1 FOR UPDATE", id).Scan(&partnerID, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}
	if revokedAt != nil {
		_ = tx.Commit(ctx)
		return nil, nil
	}
	now := time.Now()
	if _, err := tx.Exec(ctx, "UPDATE api_keys SET revoked_at=$1 WHERE id=$2", now, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AuditEvent{
		ID: randID(), Type: "auth.key.revoke", SubjectID: partnerID,
		Metadata: map[string]any{"key_id": id}, CreatedAt: now,
	}, nil
}

func (s *dbstore) ResolveAPIKey(fullKey string) *APIKey {
	ctx := context.Background()
	hash := sha256Hex(fullKey)
	row := s.pool.QueryRow(ctx,
		`SELECT id, partner_id, prefix, key_hash, scopes, ip_allowlist, expires_at, created_at, revoked_at,
		        previous_key_hash, previous_prefix, rotated_at
		 FROM api_keys WHERE key_hash=$1 OR previous_key_hash=$1 LIMIT 1`, hash)
	k, err := scanAPIKey(row)
	if err != nil || k == nil || k.RevokedAt != nil {
		return nil
	}
	return k
}

// ---------------------------------------------------------------------------
// RBAC.
// ---------------------------------------------------------------------------

func (s *dbstore) AddBinding(subjectType, subjectID, role, scopeType, scopeID string) (*RoleBinding, error) {
	if rolePermissions[role] == nil {
		return nil, ErrBadRequest
	}
	if subjectID == "" {
		return nil, ErrBadRequest
	}
	ctx := context.Background()
	id := randID()
	now := time.Now()
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO role_bindings(id, subject_type, subject_id, role, scope_type, scope_id, created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		id, subjectType, subjectID, role, scopeType, scopeID, now); err != nil {
		return nil, err
	}
	return &RoleBinding{
		ID: id, SubjectType: subjectType, SubjectID: subjectID, Role: role,
		ScopeType: scopeType, ScopeID: scopeID, CreatedAt: now,
	}, nil
}

func (s *dbstore) ListBindings(subjectType, subjectID string) []*RoleBinding {
	ctx := context.Background()
	q := "SELECT id, subject_type, subject_id, role, scope_type, scope_id, created_at FROM role_bindings"
	args := []any{}
	where := []string{}
	if subjectType != "" {
		where = append(where, "subject_type=$1")
		args = append(args, subjectType)
	}
	if subjectID != "" {
		where = append(where, fmt.Sprintf("subject_id=$%d", len(args)+1))
		args = append(args, subjectID)
	}
	if len(where) > 0 {
		q += " WHERE " + joinStrings(where, " AND ")
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]*RoleBinding, 0)
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil
		}
		out = append(out, b)
	}
	return out
}

func (s *dbstore) DeleteBinding(id string) error {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, "DELETE FROM role_bindings WHERE id=$1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

func (s *dbstore) BindingsForSubject(subjectID string) []*RoleBinding {
	return s.ListBindings("", subjectID)
}

func (s *dbstore) Authorize(subjectID, action, resource string) (AuthzResult, *AuditEvent) {
	end := observeDBSpan(context.Background(), "bindings.forSubject")
	bindings := s.BindingsForSubject(subjectID)
	end(nil)
	reason := make([]string, 0)
	allowed := false
	for _, b := range bindings {
		perms := RolePermissions(b.Role)
		for _, p := range perms {
			if p == "*" || p == action {
				allowed = true
				reason = append(reason, "role="+b.Role+" permits "+action)
				break
			}
		}
	}
	if !allowed {
		reason = append(reason, "no binding grants "+action)
	}
	res := AuthzResult{Allow: allowed, Reason: reason}
	var ev *AuditEvent
	if !allowed {
		ev = &AuditEvent{
			ID: randID(), Type: "auth.authz.deny", SubjectID: subjectID,
			Metadata: map[string]any{"action": action, "resource": resource},
			CreatedAt: time.Now(),
		}
	}
	return res, ev
}

// ---------------------------------------------------------------------------
// Password reset.
// ---------------------------------------------------------------------------

func (s *dbstore) PasswordResetInit(email string) (string, *AuditEvent, error) {
	u := s.UserByEmail(email)
	if u == nil {
		return "", nil, ErrUserNotFound
	}
	if u.Status == StatusClosed {
		return "", nil, ErrAccountClosed
	}
	token := randomToken(24)
	id := randID()
	now := time.Now()
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx,
		"INSERT INTO password_resets(id, user_id, token_hash, expires_at) VALUES($1,$2,$3,$4)",
		id, u.ID, sha256Hex(token), now.Add(PasswordResetTTL)); err != nil {
		return "", nil, err
	}
	ev := AuditEvent{
		ID: randID(), Type: "auth.password.reset.init", SubjectID: u.ID,
		Metadata: map[string]any{}, CreatedAt: now,
	}
	return token, &ev, nil
}

func (s *dbstore) PasswordResetConfirm(token, newPassword, mfaCode string) (*AuditEvent, error) {
	ctx := context.Background()
	hash := sha256Hex(token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var (
		rid      string
		userID   string
		usedAt   *time.Time
		expires  time.Time
	)
	err = tx.QueryRow(ctx,
		"SELECT id, user_id, used_at, expires_at FROM password_resets WHERE token_hash=$1 FOR UPDATE",
		hash).Scan(&rid, &userID, &usedAt, &expires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if usedAt != nil || time.Now().After(expires) {
		return nil, ErrInvalidToken
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if factors := s.confirmedFactors(userID); len(factors) > 0 {
		if mfaCode == "" {
			return nil, ErrMFARequired
		}
		if !s.validateMFA(userID, mfaCode) {
			return nil, ErrMFAInvalid
		}
	}
	if err := s.SetUserPassword(userID, newPassword); err != nil {
		return nil, err
	}
	now := time.Now()
	if _, err := s.pool.Exec(ctx, "UPDATE password_resets SET used_at=$1 WHERE id=$2", now, rid); err != nil {
		return nil, err
	}
	s.RevokeAllSessionsForUser(userID)
	s.resetLockout(userID)
	return &AuditEvent{
		ID: randID(), Type: "auth.password.reset.confirm", SubjectID: userID,
		Metadata: map[string]any{}, CreatedAt: now,
	}, nil
}

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

func (s *dbstore) RecordAudit(events ...*AuditEvent) {
	ctx := context.Background()
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if ev.ID == "" {
			ev.ID = randID()
		}
		if ev.CreatedAt.IsZero() {
			ev.CreatedAt = time.Now()
		}
		if ev.Metadata == nil {
			ev.Metadata = map[string]any{}
		}
		meta, _ := json.Marshal(ev.Metadata)
		_, _ = s.pool.Exec(ctx,
			"INSERT INTO audit_events(id, type, subject_id, session_id, request_id, metadata, created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
			ev.ID, ev.Type, ev.SubjectID, ev.SessionID, ev.RequestID, meta, ev.CreatedAt)
	}
}

func (s *dbstore) ListAudit() []AuditEvent {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx,
		"SELECT id, type, subject_id, session_id, request_id, metadata, created_at FROM audit_events ORDER BY created_at")
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]AuditEvent, 0)
	for rows.Next() {
		var ev AuditEvent
		var meta []byte
		if err := rows.Scan(&ev.ID, &ev.Type, &ev.SubjectID, &ev.SessionID, &ev.RequestID, &meta, &ev.CreatedAt); err != nil {
			return nil
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &ev.Metadata)
		}
		if ev.Metadata == nil {
			ev.Metadata = map[string]any{}
		}
		out = append(out, ev)
	}
	return out
}

// ---------------------------------------------------------------------------
// scan helpers.
// ---------------------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var u User
	var status string
	var closedAt *time.Time
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &status, &u.CreatedAt, &u.UpdatedAt, &closedAt); err != nil {
		return nil, err
	}
	u.Status = UserStatus(status)
	u.ClosedAt = closedAt
	return &u, nil
}

func scanSession(row scanner) (*Session, error) {
	var s Session
	if err := row.Scan(&s.ID, &s.UserID, &s.RefreshTokenHash, &s.Issuer, &s.IssuedAt, &s.LastSeenAt, &s.ExpiresAt, &s.RevokedAt); err != nil {
		return nil, err
	}
	return &s, nil
}

func scanFactor(row scanner, enc *db.Encryptor) (*MFAFactor, error) {
	var (
		f         MFAFactor
		encSecret []byte
		typ       string
		disabled  *time.Time
	)
	if err := row.Scan(&f.ID, &f.UserID, &typ, &encSecret, &f.Confirmed, &f.CreatedAt, &disabled); err != nil {
		return nil, err
	}
	f.Type = typ
	f.DisabledAt = disabled
	secret, err := enc.DecryptString(string(encSecret))
	if err != nil {
		return nil, err
	}
	f.Secret = secret
	return &f, nil
}

func scanAPIKey(row scanner) (*APIKey, error) {
	var (
		k           APIKey
		scopesJSON  []byte
		allowJSON   []byte
		prevHash    *string
		prevPrefix  *string
	)
	if err := row.Scan(&k.ID, &k.PartnerID, &k.Prefix, &k.KeyHash, &scopesJSON, &allowJSON, &k.ExpiresAt, &k.CreatedAt, &k.RevokedAt, &prevHash, &prevPrefix, &k.RotatedAt); err != nil {
		return nil, err
	}
	k.Scopes = parseStrings(scopesJSON)
	k.IPAllowlist = parseStrings(allowJSON)
	if prevHash != nil {
		k.PreviousKeyHash = *prevHash
	}
	if prevPrefix != nil {
		k.PreviousPrefix = *prevPrefix
	}
	return &k, nil
}

func scanBinding(row scanner) (*RoleBinding, error) {
	var b RoleBinding
	if err := row.Scan(&b.ID, &b.SubjectType, &b.SubjectID, &b.Role, &b.ScopeType, &b.ScopeID, &b.CreatedAt); err != nil {
		return nil, err
	}
	return &b, nil
}

func jsonScopes(scopes []string) []byte {
	if scopes == nil {
		scopes = []string{}
	}
	b, _ := json.Marshal(scopes)
	return b
}

func jsonAllowlist(allow []string) []byte {
	if allow == nil {
		allow = []string{}
	}
	b, _ := json.Marshal(allow)
	return b
}

func parseStrings(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}