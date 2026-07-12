.PHONY: build test run lint docker-build docker-run migrate-up migrate-down clean

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

migrate-up:
	go run ./cmd/migrate --up

migrate-down:
	go run ./cmd/migrate --down

clean:
	rm -rf bin/ coverage.out
