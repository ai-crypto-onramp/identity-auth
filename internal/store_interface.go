package internal

import "time"

// ---------------------------------------------------------------------------
// Store interface: the persistence contract used by the API layer. The
// in-memory *store (store.go) and the PostgreSQL-backed *dbstore.Store
// (db/store.go) both implement it. Handlers depend on this interface rather
// than a concrete pointer so the runtime can pick the backend via DB_URL.
// ---------------------------------------------------------------------------

// Store is the persistence surface for the identity-auth service.
type Store interface {
	// Users.
	CreateUser(email, password string) (*User, string, error)
	VerifyUserToken(token string) (*User, error)
	VerifyUser(uid string) error
	UserByID(id string) *User
	UserByEmail(email string) *User
	UpdateUserEmail(id, email string) (*User, error)
	SoftDeleteUser(id string) error
	SetUserPassword(id, password string) error
	RevokeAllSessionsForUser(userID string)

	// Sessions + lockouts.
	Login(email, password, mfaCode string, cfg *Config) (*LoginResult, *AuditEvent, error)
	Refresh(refreshToken string, cfg *Config) (*LoginResult, *AuditEvent, error)
	Logout(sessionID string) (*AuditEvent, error)
	RevokeSession(sessionID string) error
	ListSessions(userID string) []*Session
	SessionByID(sid string) (*Session, bool)
	UnlockUser(userID string) error

	// MFA.
	EnrollMFA(userID string, cfg *Config) (*MFAEnrollResult, *AuditEvent, error)
	VerifyMFA(userID, code1, code2 string) (*AuditEvent, error)
	GenerateRecoveryCodes(userID string) ([]string, *AuditEvent, error)
	DisableFactor(userID, factorID string) (*AuditEvent, error)

	// API keys.
	CreateAPIKey(partnerID string, scopes, ipAllowlist []string, expiresAt *time.Time) (*APIKeyResult, *AuditEvent, error)
	ListAPIKeys(partnerID string) []*APIKey
	RotateAPIKey(id string) (*APIKeyResult, *AuditEvent, error)
	RevokeAPIKey(id string) (*AuditEvent, error)
	ResolveAPIKey(fullKey string) *APIKey

	// RBAC.
	AddBinding(subjectType, subjectID, role, scopeType, scopeID string) (*RoleBinding, error)
	ListBindings(subjectType, subjectID string) []*RoleBinding
	DeleteBinding(id string) error
	BindingsForSubject(subjectID string) []*RoleBinding
	Authorize(subjectID, action, resource string) (AuthzResult, *AuditEvent)

	// Password reset.
	PasswordResetInit(email string) (string, *AuditEvent, error)
	PasswordResetConfirm(token, newPassword, mfaCode string) (*AuditEvent, error)

	// Audit.
	RecordAudit(events ...*AuditEvent)
	ListAudit() []AuditEvent

	// Lockout introspection (used by tests/admin handlers).
	isLocked(userID string) bool
}