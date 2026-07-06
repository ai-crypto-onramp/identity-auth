// Package main implements a small CLI that applies the embedded migrations to
// the database referenced by DB_URL. It backs the `make migrate-up` /
// `make migrate-down` Makefile targets so contributors do not need to install
// the golang-migrate binary locally.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ai-crypto-onramp/identity-auth/internal/db"
	"github.com/golang-migrate/migrate/v4"
)

func main() {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DB_URL environment variable is required")
		os.Exit(2)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]

	switch cmd {
	case "up":
		if err := db.MigrateUp(dsn); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("migrations already up to date")
				return
			}
			fatal(err)
		}
		fmt.Println("migrations applied")
	case "down":
		if err := db.MigrateDown(dsn); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				fmt.Println("no migrations to roll back")
				return
			}
			fatal(err)
		}
		fmt.Println("migrations rolled back")
	case "force":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "force requires a version argument")
			os.Exit(2)
		}
		if err := db.MigrateForce(dsn, os.Args[2]); err != nil {
			fatal(err)
		}
		fmt.Println("migration version forced")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: migrate [up|down|force <version>]")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
	os.Exit(1)
}