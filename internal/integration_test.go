//go:build integration

// Integration tests for the identity-auth service against real Postgres +
// Redis. These tests are skipped under the normal `go test` run because they
// require the `integration` build tag and live dependencies.
//
// Run with:
//
//	make test-integration
//
// Or directly:
//
//	go test -tags=integration -race ./...
//
// The tests expect the following env vars (set by docker-compose or GH Actions
// services):
//
//	TEST_DB_URL  — Postgres DSN, e.g. postgres://user:pass@localhost:5432/identity_auth_test?sslmode=disable
//	TEST_REDIS_URL — Redis URL, e.g. redis://localhost:6379/0
package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/identity-auth/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// testDBURL returns the integration test Postgres DSN.
func testDBURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DB_URL")
	if u == "" {
		u = "postgres://postgres:postgres@localhost:5432/identity_auth_test?sslmode=disable"
	}
	return u
}

// testRedisURL returns the integration test Redis address.
func testRedisURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_REDIS_URL")
	if u == "" {
		u = "redis://localhost:6379/0"
	}
	return u
}

// TestMigrateUpAgainstRealPostgres applies migrations to a real Postgres
// instance and verifies the schema_migrations table + seeded roles exist.
func TestMigrateUpAgainstRealPostgres(t *testing.T) {
	os.Setenv("DB_URL", testDBURL(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := db.DefaultConfig()
	pool, err := db.Pool(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS schema_migrations, audit_events, lockouts, password_resets, role_bindings, roles, api_keys, mfa_recovery_codes, mfa_factors, sessions, users CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}

	n, err := db.MigrateUp(ctx, pool)
	if err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 migration applied, got %d", n)
	}

	// schema_migrations should have the applied version.
	var version int
	err = pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Fatalf("query max version: %v", err)
	}
	if version < 1 {
		t.Errorf("expected version >= 1, got %d", version)
	}

	// Seeded roles must be present.
	rows, err := pool.Query(ctx, "SELECT name FROM roles ORDER BY name")
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		names = append(names, n)
	}
	want := map[string]bool{
		"user": true, "partner_admin": true, "partner_api": true,
		"support": true, "compliance": true, "ops": true, "admin": true,
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected role %q", n)
		}
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("missing roles: %v", want)
	}

	// Migrate down should roll back cleanly.
	dn, err := db.MigrateDown(ctx, pool)
	if err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if dn != 1 {
		t.Errorf("expected 1 down migration, got %d", dn)
	}
}

// TestPostgresUserInsert verifies a user row round-trips through the pool.
func TestPostgresUserInsert(t *testing.T) {
	os.Setenv("DB_URL", testDBURL(t))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := db.Pool(ctx, db.DefaultConfig())
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	if _, err := db.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	id := "itest-" + randID(8)
	_, err = pool.Exec(ctx,
		"INSERT INTO users(id, email, password_hash, status) VALUES($1, $2, $3, 'active') ON CONFLICT DO NOTHING",
		id, id+"@example.com", "hash")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var gotEmail string
	err = pool.QueryRow(ctx, "SELECT email FROM users WHERE id=$1", id).Scan(&gotEmail)
	if err != nil {
		t.Fatalf("query user: %v", err)
	}
	if gotEmail != id+"@example.com" {
		t.Errorf("email: want %q got %q", id+"@example.com", gotEmail)
	}

	// cleanup
	_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id=$1", id)
}

// TestRedisPing verifies Redis is reachable and a SET/GET round-trips.
func TestRedisPing(t *testing.T) {
	opt, err := redis.ParseURL(testRedisURL(t))
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	client := redis.NewClient(opt)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	key := "identity_auth_itest:" + randID(8)
	if err := client.Set(ctx, key, "value", time.Minute).Err(); err != nil {
		t.Fatalf("redis set: %v", err)
	}
	val, err := client.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("redis get: %v", err)
	}
	if val != "value" {
		t.Errorf("redis get: want %q got %q", "value", val)
	}
	_ = client.Del(ctx, key)
}

// TestPostgresPoolHealth verifies the pool's health-check query works.
func TestPostgresPoolHealth(t *testing.T) {
	os.Setenv("DB_URL", testDBURL(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.Pool(ctx, db.DefaultConfig())
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	var one int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("SELECT 1: %v", err)
	}
	if one != 1 {
		t.Errorf("SELECT 1: want 1 got %d", one)
	}

	// Confirm pool is a *pgxpool.Pool (compile-time assertion of API shape).
	var _ *pgxpool.Pool = pool
}