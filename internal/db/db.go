// Package db provides PostgreSQL connection pooling (pgx) and migration
// tooling (golang-migrate) for the Identity & Auth service. The DSN is
// read from the DB_URL environment variable as specified in README.md.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // register postgres driver
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	migrations "github.com/ai-crypto-onramp/identity-auth/migrations"
)

// Config holds tunable parameters for the connection pool.
type Config struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	ConnectTimeout  time.Duration
}

// DefaultConfig builds a Config from the given DSN with sensible defaults.
func DefaultConfig(dsn string) Config {
	return Config{
		DSN:             dsn,
		MaxConns:        10,
		MinConns:        1,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
		ConnectTimeout:  5 * time.Second,
	}
}

// FromEnv reads DB_URL from the environment and returns a default Config.
func FromEnv(getenv func(string) string) (Config, error) {
	dsn := getenv("DB_URL")
	if dsn == "" {
		return Config{}, errors.New("DB_URL is required")
	}
	return DefaultConfig(dsn), nil
}

// Pool opens and configures a pgx connection pool, then pings the database.
func Pool(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	if cfg.DSN == "" {
		return nil, errors.New("db: empty DSN")
	}
	parsed, err := url.Parse(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN: %w", err)
	}
	if parsed.Scheme == "" {
		return nil, errors.New("db: DSN must include a scheme (postgres://)")
	}

	pcfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: parse config: %w", err)
	}
	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pcfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		pcfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pcfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.ConnectTimeout > 0 {
		pcfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}

// MigrationsFS returns the embedded migrations directory as an fs.FS.
func MigrationsFS() fs.FS {
	sub, err := fs.Sub(migrations.Files, ".")
	if err != nil {
		panic(fmt.Sprintf("db: resolve migrations sub fs: %v", err))
	}
	return sub
}

// MigrateUp applies all pending migrations to the database referenced by dsn.
func MigrateUp(dsn string) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: migrate up: %w", err)
	}
	return nil
}

// MigrateDown rolls back all applied migrations.
func MigrateDown(dsn string) error {
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: migrate down: %w", err)
	}
	return nil
}

// MigrateForce sets the migration version to v without running migrations,
// used to recover from dirty (failed) migration state. v must be a non-empty
// numeric string.
func MigrateForce(dsn, v string) error {
	if v == "" {
		return errors.New("db: migrate force: version required")
	}
	var version uint
	if _, err := fmt.Sscanf(v, "%d", &version); err != nil {
		return fmt.Errorf("db: migrate force: parse version: %w", err)
	}
	m, err := newMigrate(dsn)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Force(int(version)); err != nil {
		return fmt.Errorf("db: migrate force: %w", err)
	}
	return nil
}

func newMigrate(dsn string) (*migrate.Migrate, error) {
	src, err := iofs.New(MigrationsFS(), ".")
	if err != nil {
		return nil, fmt.Errorf("db: migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: init migrate: %w", err)
	}
	return m, nil
}