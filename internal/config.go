package internal

import (
	"os"
	"strconv"
	"time"
)

// Config holds runtime configuration derived from environment variables.
type Config struct {
	JWTSecret  string
	JWTIssuer  string
	MFAIssuer  string
	LockoutThreshold int
	LockoutBaseSeconds int
	PasswordMinLength int
}

// DefaultConfig returns sensible defaults for tests and dev.
func DefaultConfig() *Config {
	return &Config{
		JWTSecret:          "dev-secret",
		JWTIssuer:          "identity-auth",
		MFAIssuer:          "ai-crypto-onramp",
		LockoutThreshold:   LockoutThreshold,
		LockoutBaseSeconds: LockoutBaseSeconds,
		PasswordMinLength:  8,
	}
}

// ConfigFromEnv reads configuration from environment variables with defaults.
func ConfigFromEnv() *Config {
	cfg := DefaultConfig()
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("JWT_ISSUER"); v != "" {
		cfg.JWTIssuer = v
	}
	if v := os.Getenv("MFA_ISSUER"); v != "" {
		cfg.MFAIssuer = v
	}
	if v := os.Getenv("LOCKOUT_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.LockoutThreshold = n
		}
	}
	if v := os.Getenv("LOCKOUT_BASE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.LockoutBaseSeconds = n
		}
	}
	if v := os.Getenv("PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.PasswordMinLength = n
		}
	}
	return cfg
}

// AccessTokenTTLRef keeps the constant reachable for tests.
const AccessTokenTTLRef = 15 * time.Minute