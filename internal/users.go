package internal

import (
	"errors"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// User domain: registration, verification, profile, soft-delete, password
// policy.
// ---------------------------------------------------------------------------

var (
	ErrEmailTaken        = errors.New("email already registered")
	ErrWeakPassword      = errors.New("password does not meet policy")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked     = errors.New("account locked")
	ErrAccountClosed     = errors.New("account closed")
	ErrAccountPending    = errors.New("account pending verification")
	ErrMFARequired       = errors.New("mfa code required")
	ErrMFAInvalid        = errors.New("invalid mfa code")
	ErrMFANotEnrolled    = errors.New("mfa not enrolled")
	ErrFactorNotConfirmed = errors.New("mfa factor not confirmed")
	ErrSessionNotFound   = errors.New("session not found")
	ErrRefreshTokenInvalid = errors.New("refresh token invalid or revoked")
	ErrAPIKeyNotFound    = errors.New("api key not found")
	ErrBindingNotFound   = errors.New("role binding not found")
	ErrFactorNotFound    = errors.New("mfa factor not found")
	ErrForbidden         = errors.New("forbidden")
	ErrBadRequest        = errors.New("bad request")
)

// passwordPolicy validates the chosen password against the simple rules.
func passwordPolicy(pw string) error {
	if len(pw) < 8 {
		return ErrWeakPassword
	}
	if pw == "password" || pw == "12345678" {
		return ErrWeakPassword
	}
	return nil
}

// normalizeEmail lowercases and trims for uniqueness comparisons.
func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// CreateUser registers a new pending user and creates a verification token.
func (s *store) CreateUser(email, password string) (*User, string, error) {
	email = normalizeEmail(email)
	if email == "" {
		return nil, "", ErrBadRequest
	}
	if err := passwordPolicy(password); err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByEmail[email]; ok {
		return nil, "", ErrEmailTaken
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	u := &User{
		ID:           randID(12),
		Email:        email,
		PasswordHash: hash,
		Status:       StatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.users[u.ID] = u
	s.usersByEmail[email] = u.ID
	token := randomToken(24)
	s.verification[token] = u.ID
	return u, token, nil
}

// VerifyUser flips a pending user to active; requires the user to be pending.
func (s *store) VerifyUserToken(token string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, ok := s.verification[token]
	if !ok {
		return nil, ErrInvalidToken
	}
	delete(s.verification, token)
	u, ok := s.users[uid]
	if !ok {
		return nil, ErrUserNotFound
	}
	if u.Status != StatusPending {
		return nil, ErrInvalidToken
	}
	u.Status = StatusActive
	u.UpdatedAt = time.Now()
	return u, nil
}

// VerifyUser is a convenience used by test seeders.
func (s *store) VerifyUser(uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[uid]
	if !ok {
		return ErrUserNotFound
	}
	if u.Status != StatusPending {
		return ErrInvalidToken
	}
	u.Status = StatusActive
	u.UpdatedAt = time.Now()
	return nil
}

// UserByID returns a user or nil.
func (s *store) UserByID(id string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[id]
}

// UserByEmail returns a user or nil.
func (s *store) UserByEmail(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.usersByEmail[normalizeEmail(email)]
	if !ok {
		return nil
	}
	return s.users[uid]
}

// UpdateUserEmail updates email if not taken.
func (s *store) UpdateUserEmail(id, email string) (*User, error) {
	email = normalizeEmail(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	if u.Status == StatusClosed {
		return nil, ErrAccountClosed
	}
	if email == "" {
		return nil, ErrBadRequest
	}
	if existing, ok := s.usersByEmail[email]; ok && existing != id {
		return nil, ErrEmailTaken
	}
	delete(s.usersByEmail, u.Email)
	u.Email = email
	u.UpdatedAt = time.Now()
	s.usersByEmail[email] = id
	return u, nil
}

// SoftDeleteUser marks a user closed.
func (s *store) SoftDeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	now := time.Now()
	u.Status = StatusClosed
	u.UpdatedAt = now
	u.ClosedAt = &now
	// Revoke all sessions.
	for _, sess := range s.sessions {
		if sess.UserID == id && sess.RevokedAt == nil {
			t := now
			sess.RevokedAt = &t
		}
	}
	return nil
}

// SetUserPassword updates the password hash (used by reset flow).
func (s *store) SetUserPassword(id, password string) error {
	if err := passwordPolicy(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	u.PasswordHash = hash
	u.UpdatedAt = time.Now()
	return nil
}

// verifyUserPassword is a read-only helper.
func (s *store) verifyUserPassword(u *User, password string) bool {
	if u == nil {
		return false
	}
	return verifyPassword(u.PasswordHash, password)
}

// RevokeAllSessionsForUser invalidates every session belonging to the user.
func (s *store) RevokeAllSessionsForUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			t := now
			sess.RevokedAt = &t
			delete(s.sessionsByRT, sess.RefreshTokenHash)
		}
	}
}