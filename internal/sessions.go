package internal

import (
	"context"
	"crypto/subtle"
	"time"
)

// ---------------------------------------------------------------------------
// Sessions: login, refresh rotation, logout, revoke, list, lockout.
// ---------------------------------------------------------------------------

// LockoutThreshold is the number of consecutive failures before lockout.
const LockoutThreshold = 5

// LockoutBaseSeconds is the initial lockout duration; doubled each lockout.
const LockoutBaseSeconds = 30

// SessionTTL is the lifetime of a session (refresh token absolute TTL).
const SessionTTL = 30 * 24 * time.Hour

// AccessTokenTTL is the JWT lifetime.
const AccessTokenTTL = 15 * time.Minute

// LoginResult is the login response shape.
type LoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// recordFailure increments the lockout counter for the user and locks if needed.
func (s *store) recordFailure(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.lockouts[userID]
	if !ok {
		l = &Lockout{UserID: userID}
		s.lockouts[userID] = l
	}
	l.FailCount++
	if l.FailCount >= LockoutThreshold {
		dur := time.Duration(LockoutBaseSeconds) * time.Second
		dur = dur << uint(l.FailCount-LockoutThreshold) // exponential
		if dur > 24*time.Hour {
			dur = 24 * time.Hour
		}
		until := time.Now().Add(dur)
		l.LockedUntil = &until
	}
	l.UpdatedAt = time.Now()
}

// isLocked reports whether the user is currently locked (with backoff active).
func (s *store) isLocked(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.lockouts[userID]
	if !ok || l.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*l.LockedUntil)
}

// resetLockout clears failures on a successful login.
func (s *store) resetLockout(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.lockouts, userID)
}

// UnlockUser clears the lockout (admin path).
func (s *store) UnlockUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrUserNotFound
	}
	delete(s.lockouts, userID)
	return nil
}

// Login authenticates the user, optionally requiring MFA. On success it
// returns access+refresh tokens. The refresh token is stored hashed.
func (s *store) Login(email, password, mfaCode string, cfg *Config) (*LoginResult, *AuditEvent, error) {
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
	if !s.verifyUserPassword(u, password) {
		end = observeDBSpan(ctx, "lockouts.recordFailure")
		s.recordFailure(u.ID)
		end(nil)
		if s.isLocked(u.ID) {
			return nil, nil, ErrAccountLocked
		}
		return nil, nil, ErrInvalidCredentials
	}
	// Password ok — check MFA requirement.
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

// issueSession creates a new session, access JWT, and refresh token.
func (s *store) issueSession(userID string, cfg *Config) (*LoginResult, *AuditEvent, error) {
	sid := randID()
	refresh := randomToken(32)
	refreshHash := sha256Hex(refresh)
	now := time.Now()
	sess := &Session{
		ID:               sid,
		UserID:           userID,
		RefreshTokenHash: refreshHash,
		Issuer:           cfg.JWTIssuer,
		IssuedAt:         now,
		LastSeenAt:       now,
		ExpiresAt:        now.Add(SessionTTL),
	}
	end := observeDBSpan(context.Background(), "sessions.insert")
	s.mu.Lock()
	s.sessions[sid] = sess
	s.sessionsByRT[refreshHash] = sid
	s.mu.Unlock()
	end(nil)
	end = observeRedisSpan(context.Background(), "SET refresh_allowlist")
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

// Refresh validates the refresh token, rotates it (old invalidated), and
// returns a fresh access+refresh pair. Reused old refresh tokens are rejected.
func (s *store) Refresh(refreshToken string, cfg *Config) (*LoginResult, *AuditEvent, error) {
	hash := sha256Hex(refreshToken)
	s.mu.Lock()
	sid, ok := s.sessionsByRT[hash]
	sess := (*Session)(nil)
	if ok {
		sess = s.sessions[sid]
	}
	if !ok || sess == nil {
		// Check whether this is a previously-rotated (chain-superseded) token.
		if _, reused := s.refreshChain[hash]; reused {
			s.mu.Unlock()
			// Reuse detected: revoke the chain's session.
			s.RevokeSession(s.refreshChain[hash])
			return nil, nil, ErrRefreshTokenInvalid
		}
		s.mu.Unlock()
		return nil, nil, ErrRefreshTokenInvalid
	}
	if sess.RevokedAt != nil {
		s.mu.Unlock()
		return nil, nil, ErrRefreshTokenInvalid
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Unlock()
		return nil, nil, ErrRefreshTokenInvalid
	}
	userID := sess.UserID
	// Rotate: invalidate old refresh, link chain for reuse detection.
	delete(s.sessionsByRT, hash)
	newRT := randomToken(32)
	newHash := sha256Hex(newRT)
	sess.RefreshTokenHash = newHash
	sess.LastSeenAt = time.Now()
	s.sessionsByRT[newHash] = sid
	s.refreshChain[hash] = sid
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.refresh",
		SubjectID: userID,
		SessionID: sid,
		Metadata:  map[string]any{},
		CreatedAt: time.Now(),
	}
	s.mu.Unlock()

	claims := JWTClaims{
		Sub: userID,
		Sid: sid,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(AccessTokenTTL).Unix(),
		Iss: cfg.JWTIssuer,
	}
	access, err := signJWT(claims, cfg.JWTSecret)
	if err != nil {
		return nil, nil, err
	}
	return &LoginResult{AccessToken: access, RefreshToken: newRT, ExpiresIn: int64(AccessTokenTTL.Seconds())}, &ev, nil
}

// Logout revokes the session identified by the access JWT's sid claim.
func (s *store) Logout(sessionID string) (*AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.RevokedAt != nil {
		return nil, nil
	}
	now := time.Now()
	sess.RevokedAt = &now
	delete(s.sessionsByRT, sess.RefreshTokenHash)
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.logout",
		SubjectID: sess.UserID,
		SessionID: sessionID,
		Metadata:  map[string]any{},
		CreatedAt: now,
	}
	return &ev, nil
}

// RevokeSession revokes a specific session by id (idempotent).
func (s *store) RevokeSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if sess.RevokedAt != nil {
		return nil
	}
	now := time.Now()
	sess.RevokedAt = &now
	delete(s.sessionsByRT, sess.RefreshTokenHash)
	return nil
}

// ListSessions returns active (non-revoked, non-expired) sessions for the user.
func (s *store) ListSessions(userID string) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]*Session, 0)
	for _, sess := range s.sessions {
		if sess.UserID != userID {
			continue
		}
		if sess.RevokedAt != nil {
			continue
		}
		if now.After(sess.ExpiresAt) {
			continue
		}
		out = append(out, sess)
	}
	return out
}

// SessionByID returns the session by id and a presence flag. The session is
// considered "found" if it exists and is not revoked.
func (s *store) SessionByID(sid string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sid]
	if !ok || sess == nil || sess.RevokedAt != nil {
		return nil, false
	}
	return sess, true
}

// constantTimeEqual is a small helper exposing subtle.ConstantTimeCompare.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}