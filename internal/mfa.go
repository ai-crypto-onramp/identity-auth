package internal

import (
	"time"
)

// ---------------------------------------------------------------------------
// MFA: enroll, verify (two consecutive OTPs), recovery codes, validation,
// factor disable. Login-time challenge handled in sessions.go.
// ---------------------------------------------------------------------------

// MFATTL is how long an unconfirmed factor remains valid before pruning.
const MFATTL = 10 * time.Minute

// MFAEnrollResult is returned by EnrollMFA.
type MFAEnrollResult struct {
	FactorID string `json:"factor_id"`
	Secret   string `json:"secret"`
	QRURI    string `json:"qr_uri"`
}

// EnrollMFA generates a new TOTP secret for the user (unconfirmed).
func (s *store) EnrollMFA(userID string, cfg *Config) (*MFAEnrollResult, *AuditEvent, error) {
	secret, err := randomTOTPSecret()
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, nil, ErrUserNotFound
	}
	if u.Status == StatusClosed {
		return nil, nil, ErrAccountClosed
	}
	id := randID()
	f := &MFAFactor{
		ID:        id,
		UserID:    userID,
		Type:      "TOTP",
		Secret:    secret,
		Confirmed: false,
		CreatedAt: time.Now(),
	}
	s.mfaFactors[id] = f
	s.mfaByUser[userID] = append(s.mfaByUser[userID], id)
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.mfa.enroll",
		SubjectID: userID,
		Metadata:  map[string]any{"factor_id": id},
		CreatedAt: time.Now(),
	}
	return &MFAEnrollResult{
		FactorID: id,
		Secret:   secret,
		QRURI:    otpURI(cfg.MFAIssuer, u.Email, secret),
	}, &ev, nil
}

// VerifyMFA confirms enrollment by requiring two consecutive valid OTPs
// (current window and the next/previous step). Once confirmed, the factor is
// active and login will challenge it.
func (s *store) VerifyMFA(userID, code1, code2 string) (*AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.latestUnconfirmedFactor(userID)
	if !ok {
		return nil, ErrFactorNotConfirmed
	}
	now := time.Now()
	// code1 must be valid for the current step; code2 must be valid for the
	// immediately adjacent step (prev or next) to prove consecutive possession.
	if !totpWindowValid(f.Secret, code1, now, 1) {
		return nil, ErrMFAInvalid
	}
	// code2 must NOT match code1's step and must match an adjacent step.
	if code1 == code2 {
		return nil, ErrMFAInvalid
	}
	// Try prev and next steps only (window=0 on the offset time).
	prev := now.Add(-30 * time.Second)
	next := now.Add(30 * time.Second)
	if !totpWindowValid(f.Secret, code2, prev, 0) && !totpWindowValid(f.Secret, code2, next, 0) {
		return nil, ErrMFAInvalid
	}
	f.Confirmed = true
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.mfa.verify",
		SubjectID: userID,
		Metadata:  map[string]any{"factor_id": f.ID},
		CreatedAt: now,
	}
	return &ev, nil
}

// latestUnconfirmedFactor returns the most recent unconfirmed TOTP factor.
func (s *store) latestUnconfirmedFactor(userID string) (*MFAFactor, bool) {
	ids := s.mfaByUser[userID]
	for i := len(ids) - 1; i >= 0; i-- {
		f := s.mfaFactors[ids[i]]
		if f != nil && !f.Confirmed && f.DisabledAt == nil {
			return f, true
		}
	}
	return nil, false
}

// confirmedFactors returns active (confirmed, not disabled) TOTP factors.
func (s *store) confirmedFactors(userID string) []*MFAFactor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.mfaByUser[userID]
	out := make([]*MFAFactor, 0)
	for _, id := range ids {
		f := s.mfaFactors[id]
		if f != nil && f.Confirmed && f.DisabledAt == nil {
			out = append(out, f)
		}
	}
	return out
}

// validateMFA returns true if code matches any confirmed factor or recovery code.
func (s *store) validateMFA(userID, code string) bool {
	if len(code) == 0 {
		return false
	}
	// Try TOTP factors first.
	factors := s.confirmedFactors(userID)
	for _, f := range factors {
		if totpWindowValid(f.Secret, code, time.Now(), 1) {
			return true
		}
	}
	// Try recovery codes (single-use, hashed).
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rc := range s.recoveryCodes {
		if rc.UserID != userID || rc.UsedAt != nil {
			continue
		}
		if constantTimeEqual(sha256Hex(code), rc.Hash) {
			now := time.Now()
			rc.UsedAt = &now
			return true
		}
	}
	return false
}

// GenerateRecoveryCodes creates 10 single-use recovery codes (hashed).
// Returns the plaintext codes once.
func (s *store) GenerateRecoveryCodes(userID string) ([]string, *AuditEvent, error) {
	codes := make([]string, 0, 10)
	hashed := make([]*RecoveryCode, 0, 10)
	for i := 0; i < 10; i++ {
		c := randomToken(8)
		codes = append(codes, c)
		hashed = append(hashed, &RecoveryCode{
			ID:     randID(),
			UserID: userID,
			Hash:   sha256Hex(c),
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return nil, nil, ErrUserNotFound
	}
	// Invalidate prior recovery codes (re-issue semantics).
	for id, rc := range s.recoveryCodes {
		if rc.UserID == userID {
			delete(s.recoveryCodes, id)
		}
	}
	for _, rc := range hashed {
		s.recoveryCodes[rc.ID] = rc
	}
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.mfa.recovery",
		SubjectID: userID,
		Metadata:  map[string]any{"count": len(codes)},
		CreatedAt: time.Now(),
	}
	return codes, &ev, nil
}

// DisableFactor disables an MFA factor (re-auth assumed via valid token).
func (s *store) DisableFactor(userID, factorID string) (*AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.mfaFactors[factorID]
	if !ok || f.UserID != userID {
		return nil, ErrFactorNotFound
	}
	now := time.Now()
	f.DisabledAt = &now
	f.Confirmed = false
	ev := AuditEvent{
		ID:        randID(),
		Type:      "auth.mfa.disable",
		SubjectID: userID,
		Metadata:  map[string]any{"factor_id": factorID},
		CreatedAt: now,
	}
	return &ev, nil
}