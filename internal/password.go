package internal

import (
	"time"
)

// ---------------------------------------------------------------------------
// Password reset: init (single-use token), confirm (resets password,
// invalidates sessions, optional MFA re-auth).
// ---------------------------------------------------------------------------

// PasswordResetTTL is the validity window for a reset token.
const PasswordResetTTL = 30 * time.Minute

// PasswordResetInit issues a single-use reset token for the user (if exists).
// Always returns a token for the test impl; production would email the link.
func (s *store) PasswordResetInit(email string) (string, *AuditEvent, error) {
	u := s.UserByEmail(email)
	if u == nil {
		return "", nil, ErrUserNotFound
	}
	if u.Status == StatusClosed {
		return "", nil, ErrAccountClosed
	}
	token := randomToken(24)
	hash := sha256Hex(token)
	id := randID()
	pr := &PasswordReset{
		ID:        id,
		UserID:    u.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(PasswordResetTTL),
	}
	s.mu.Lock()
	s.passwordResets[id] = pr
	s.resetsByToken[hash] = id
	s.mu.Unlock()
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.password.reset.init",
		SubjectID: u.ID,
		Metadata:  map[string]any{},
		CreatedAt: time.Now(),
	}
	return token, &ev, nil
}

// PasswordResetConfirm validates the token, optionally requires MFA, sets the
// new password, and revokes all sessions.
func (s *store) PasswordResetConfirm(token, newPassword, mfaCode string) (*AuditEvent, error) {
	hash := sha256Hex(token)
	s.mu.Lock()
	rid, ok := s.resetsByToken[hash]
	if !ok {
		s.mu.Unlock()
		return nil, ErrInvalidToken
	}
	pr := s.passwordResets[rid]
	if pr == nil || pr.UsedAt != nil || time.Now().After(pr.ExpiresAt) {
		s.mu.Unlock()
		return nil, ErrInvalidToken
	}
	userID := pr.UserID
	s.mu.Unlock()

	// If MFA is enrolled, require a valid mfa_code.
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
	s.mu.Lock()
	now := time.Now()
	pr.UsedAt = &now
	delete(s.resetsByToken, hash)
	s.mu.Unlock()
	s.RevokeAllSessionsForUser(userID)
	s.resetLockout(userID)
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.password.reset.confirm",
		SubjectID: userID,
		Metadata:  map[string]any{},
		CreatedAt: now,
	}
	return &ev, nil
}