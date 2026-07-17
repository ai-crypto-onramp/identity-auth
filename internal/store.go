package internal

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// In-memory store: users, sessions, MFA factors, recovery codes, API keys,
// role bindings, password resets, lockouts, audit events, verification and
// reset tokens. All guarded by a single RWMutex — adequate for tests.
// ---------------------------------------------------------------------------

// UserStatus enumerates account states.
type UserStatus string

const (
	StatusPending   UserStatus = "PENDING"
	StatusActive    UserStatus = "ACTIVE"
	StatusLocked    UserStatus = "LOCKED"
	StatusSuspended UserStatus = "SUSPENDED"
	StatusClosed    UserStatus = "CLOSED"
)

// User is the in-memory user record.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ClosedAt     *time.Time
}

// Session is the in-memory session record.
type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	Issuer           string
	IssuedAt         time.Time
	LastSeenAt       time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
}

// MFAFactor is a TOTP factor for a user.
type MFAFactor struct {
	ID        string
	UserID    string
	Type      string // "TOTP"
	Secret    string
	Confirmed bool
	CreatedAt time.Time
	DisabledAt *time.Time
}

// RecoveryCode is a single-use recovery code (stored hashed).
type RecoveryCode struct {
	ID     string
	UserID string
	Hash   string
	UsedAt *time.Time
}

// APIKey is a partner API key (stored hashed; full key revealed once).
type APIKey struct {
	ID          string
	PartnerID   string
	Prefix      string
	KeyHash     string
	Scopes      []string
	IPAllowlist []string
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	RevokedAt   *time.Time
	// PreviousKeyHash supports dual-active rotation window.
	PreviousKeyHash string
	PreviousPrefix  string
	RotatedAt       *time.Time
}

// RoleBinding associates a subject with a role.
type RoleBinding struct {
	ID         string
	SubjectType string // "USER" or "API_KEY"
	SubjectID  string
	Role       string
	ScopeType  string // "partner" or ""
	ScopeID    string
	CreatedAt  time.Time
}

// PasswordReset is a single-use reset token (stored hashed).
type PasswordReset struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// Lockout tracks failed login attempts.
type Lockout struct {
	UserID      string
	FailCount   int
	LockedUntil *time.Time
	UpdatedAt   time.Time
}

// AuditEvent is the canonical audit record.
type AuditEvent struct {
	ID        string
	Type      string
	SubjectID string
	SessionID string
	RequestID string
	Metadata  map[string]any
	CreatedAt time.Time
}

// store is the in-memory persistence layer.
type store struct {
	mu sync.RWMutex

	users         map[string]*User            // id -> user
	usersByEmail  map[string]string           // email -> id
	verification  map[string]string           // token -> userID (email verification)
	sessions      map[string]*Session         // id -> session
	sessionsByRT  map[string]string           // refresh token hash -> session id
	refreshChain  map[string]string           // old refresh hash -> new session id (for reuse detection)
	mfaFactors    map[string]*MFAFactor       // id -> factor
	mfaByUser     map[string][]string          // user id -> factor ids
	recoveryCodes map[string]*RecoveryCode     // id -> code
	apiKeys       map[string]*APIKey           // id -> key
	apiKeysByHash map[string]string            // key hash -> key id
	roles         map[string]map[string]bool  // role -> set(permissions)
	bindings      map[string]*RoleBinding      // id -> binding
	passwordResets map[string]*PasswordReset    // id -> reset
	resetsByToken map[string]string             // token hash -> reset id
	lockouts      map[string]*Lockout          // user id -> lockout
	auditEvents   []AuditEvent
}

func newStore() *store {
	return &store{
		users:          make(map[string]*User),
		usersByEmail:   make(map[string]string),
		verification:   make(map[string]string),
		sessions:       make(map[string]*Session),
		sessionsByRT:   make(map[string]string),
		refreshChain:   make(map[string]string),
		mfaFactors:     make(map[string]*MFAFactor),
		mfaByUser:      make(map[string][]string),
		recoveryCodes:  make(map[string]*RecoveryCode),
		apiKeys:        make(map[string]*APIKey),
		apiKeysByHash:  make(map[string]string),
		roles:          make(map[string]map[string]bool),
		bindings:       make(map[string]*RoleBinding),
		passwordResets: make(map[string]*PasswordReset),
		resetsByToken:  make(map[string]string),
		lockouts:       make(map[string]*Lockout),
	}
}