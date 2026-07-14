.PHONY: build test test-integration run lint cover docker-build docker-run migrate-up migrate-down gen-rbac-bundle clean

build:
	go build -o bin/identity-auth ./cmd/identity-auth

test:
	go test ./internal/... -race -coverprofile=coverage.out -coverpkg=./internal/...

test-integration:
	go test -tags=integration -race ./cmd/... ./internal/...

run:
	go run ./cmd/identity-auth

lint:
	golangci-lint run

cover: test
	go tool cover -func=coverage.out | tail -1

docker-build:
	docker build -t ai-crypto-onramp/identity-auth .

docker-run:
	docker run --rm -p 8080:8080 ai-crypto-onramp/identity-auth

migrate-up:
	go run ./cmd/migrate --up

migrate-down:
	go run ./cmd/migrate --down

gen-rbac-bundle:
	go run ./cmd/gen-rbac-bundle -out rbac.rego

clean:
	rm -rf bin/ coverage.out rbac.rego
