.PHONY: build test run lint docker-build docker-run clean migrate-up migrate-down migrate-force

DB_URL ?= postgres://postgres:postgres@localhost:5432/identity?sslmode=disable

build:
	go build -o bin/server .

test:
	go test ./... -race -coverprofile=coverage.out -coverpkg=./...

run:
	go run .

lint:
	go vet ./...

docker-build:
	docker build -t ai-crypto-onramp/identity-auth .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/identity-auth

clean:
	rm -rf bin/ coverage.out

# Apply all pending migrations to the database referenced by DB_URL.
migrate-up:
	go run ./cmd/migrate up

# Roll back all applied migrations from the database referenced by DB_URL.
migrate-down:
	go run ./cmd/migrate down

# Force-set the migration version (used for drift recovery). Usage: make migrate-force V=<n>
migrate-force:
	go run ./cmd/migrate force $(V)
