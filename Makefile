.PHONY: build test test-race test-coverage lint vet fmt mod-tidy vulncheck clean xcaddy generate-certs docker-build docker-up docker-down

BINARY := caddy
MODULE := github.com/josuebrunel/caddy-ja3ja4

build:
	go build -tags caddy -o $(BINARY) ./cmd/caddy

test:
	go test -v -short ./...

test-race:
	go test -v -race -short ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out -short ./...

lint:
	golangci-lint run --timeout=5m

vet:
	go vet ./...

fmt:
	go fmt ./...

mod-tidy:
	go mod tidy

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

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

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down
