// Package migrations embeds the SQL migration files so they can be applied
// from the compiled binary without requiring the migrations/ directory on
// the runtime filesystem.
package migrations

import "embed"

// Files holds the embedded migration SQL files.
//
//go:embed *.sql
var Files embed.FS