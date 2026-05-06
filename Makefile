.PHONY: build test lint clean xcaddy

BINARY := caddy
MODULE := github.com/yourorg/caddy-ja3ja4

build:
	go build -o $(BINARY) ./cmd/caddy

test:
	go test -v -race ./...

test-integration:
	go test -v -run Integration ./...

lint:
	golangci-lint run

clean:
	rm -f $(BINARY)
	go clean -cache -testcache

xcaddy:
	xcaddy build \
		--with $(MODULE)=. \
		--output ./caddy

generate-certs:
	mkdir -p testdata
	openssl req -x509 -newkey rsa:2048 -keyout testdata/key.pem -out testdata/cert.pem -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

ci-test: generate-certs test
