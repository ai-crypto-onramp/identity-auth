package db

import (
	"strings"
	"testing"
)

func TestFromEnvRequiresDBURL(t *testing.T) {
	if _, err := FromEnv(func(string) string { return "" }); err == nil {
		t.Fatalf("expected error when DB_URL is empty")
	}
}

func TestFromEnvBuildsConfig(t *testing.T) {
	cfg, err := FromEnv(func(k string) string {
		if k == "DB_URL" {
			return "postgres://user:pass@localhost:5432/identity?sslmode=disable"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.DSN == "" {
		t.Fatalf("DSN empty")
	}
	if cfg.MaxConns <= 0 {
		t.Fatalf("MaxConns not set")
	}
}

func TestPoolRejectsEmptyDSN(t *testing.T) {
	if _, err := Pool(t.Context(), Config{}); err == nil {
		t.Fatalf("expected error for empty DSN")
	}
}

func TestPoolRejectsMissingScheme(t *testing.T) {
	// A protocol-relative URL parses with an empty Scheme; Pool should reject
	// it before handing off to pgxpool.
	_, err := Pool(t.Context(), DefaultConfig("//localhost:5432/identity"))
	if err == nil {
		t.Fatalf("expected error for DSN without scheme")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrationsFSNonNil(t *testing.T) {
	if fsys := MigrationsFS(); fsys == nil {
		t.Fatalf("MigrationsFS returned nil")
	}
}

func TestMigrateUpNoDSN(t *testing.T) {
	if err := MigrateUp(""); err == nil {
		t.Fatalf("expected error for empty DSN")
	}
}

func TestMigrateForceRejectsEmptyVersion(t *testing.T) {
	if err := MigrateForce("postgres://localhost/db", ""); err == nil {
		t.Fatalf("expected error for empty version")
	}
}

func TestMigrateForceRejectsNonNumeric(t *testing.T) {
	if err := MigrateForce("postgres://localhost/db", "abc"); err == nil {
		t.Fatalf("expected error for non-numeric version")
	}
}

func TestConfigDefaultsNonZero(t *testing.T) {
	cfg := DefaultConfig("postgres://localhost/db")
	if cfg.MaxConnLifetime == 0 || cfg.ConnectTimeout == 0 || cfg.MaxConns == 0 {
		t.Fatalf("DefaultConfig produced zero values: %+v", cfg)
	}
}