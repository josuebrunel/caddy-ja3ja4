.PHONY: build test test-race test-coverage bench fuzz lint vet fmt mod-tidy mod-check vulncheck clean xcaddy generate-certs docker-build docker-up docker-down docker-logs docker-logs-raw docker-test

BINARY := caddy
MODULE := github.com/josuebrunel/caddy-ja3ja4

# Pinned so builds and scans are reproducible. Bump deliberately; XCADDY_VERSION
# must match the Dockerfile and the CI workflows.
XCADDY_VERSION ?= v0.4.7
GOVULNCHECK_VERSION ?= v1.8.0

build:
	go build -o $(BINARY) ./cmd/caddy

test:
	go test -v -short ./...

test-race:
	go test -v -race -short ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out -short ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Fuzz the JA3 builder; FUZZTIME=5m for a longer session.
FUZZTIME ?= 30s
fuzz:
	go test -run '^$$' -fuzz FuzzComputeJA3 -fuzztime $(FUZZTIME) .

lint:
	golangci-lint run --timeout=5m

vet:
	go vet ./...

fmt:
	go fmt ./...

mod-tidy:
	go mod tidy

# Fails when go.mod/go.sum are not what `go mod tidy` would write (used by CI).
mod-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

clean:
	rm -f $(BINARY) coverage.out
	go clean -cache -testcache

xcaddy:
	xcaddy build \
		--with $(MODULE)=. \
		--output ./caddy

generate-certs:
	mkdir -p testdata
	openssl req -x509 -newkey rsa:2048 -keyout testdata/key.pem -out testdata/cert.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
	# Test-only key: make it readable by the non-root user inside the compose container.
	chmod 644 testdata/key.pem

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

# Follow the access log, one compact line per request (needs jq).
docker-logs:
	docker compose logs -f --no-log-prefix --since 1m caddy | jq --unbuffered -R -c -f scripts/access-log.jq

# Follow Caddy's complete, unfiltered log output.
docker-logs-raw:
	docker compose logs -f --no-log-prefix --since 1m caddy

# Start the stack, send requests with different TLS/HTTP settings, show what was logged.
docker-test: docker-up
	docker compose --profile tools run --rm client
	@echo
	@echo "--- access log ---"
	@docker compose logs --no-log-prefix --since 1m caddy | jq -R -c -f scripts/access-log.jq
