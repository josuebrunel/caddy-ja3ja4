# caddy-ja3ja4

[![Go Reference](https://pkg.go.dev/badge/github.com/josuebrunel/caddy-ja3ja4.svg)](https://pkg.go.dev/github.com/josuebrunel/caddy-ja3ja4)
[![CI](https://github.com/josuebrunel/caddy-ja3ja4/actions/workflows/ci.yml/badge.svg)](https://github.com/josuebrunel/caddy-ja3ja4/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/josuebrunel/caddy-ja3ja4)](https://goreportcard.com/report/github.com/josuebrunel/caddy-ja3ja4)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-ready Caddy v2 module for TLS fingerprinting using [JA3](https://github.com/salesforce/ja3) and [JA4+](https://github.com/FoxIO-LLC/ja4).

## Features

- **JA3 Fingerprinting** -- Full JA3 spec implementation: MD5 hash of TLS ClientHello parameters (version, ciphers, extensions, curves, point formats)
- **JA4 Fingerprinting** -- Spec-compliant JA4 via `github.com/exaring/ja4plus` library
- **Placeholder Integration** -- Expose fingerprints as `{tls.ja3}`, `{tls.ja4}`, `{tls.ja3_raw}`, and `{tls.ja3_sorted}` for use in logging, routing, headers, and matchers
- **Zero Global Side Effects** -- Per-connection fingerprint storage preserves TLS session resumption
- **Extension Sorting** -- Optional `sort_ja3_extensions` flag to counter extension-randomization evasion techniques
- **Graceful Degradation** -- Safely handles non-TLS connections, HTTP/3, and edge cases
- **Caddy 2.11+ Compatible** -- Uses `tls.context` HandshakeContext module architecture

## Installation

### Option 1: Build with xcaddy (Recommended)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

xcaddy build \
  --with github.com/josuebrunel/caddy-ja3ja4@latest \
  --output ./caddy
```

### Option 2: Build from Source

```bash
git clone https://github.com/josuebrunel/caddy-ja3ja4.git
cd caddy-ja3ja4
make xcaddy
```

### Option 3: Docker Compose

```bash
docker compose up -d
```

## Configuration

### Caddyfile

The plugin is configured entirely through the HTTP handler. No TLS block configuration is needed.

```caddyfile
{
    order ja3_ja4 first
}

example.com {
    ja3_ja4

    log {
        output file /var/log/caddy/access.log
        format json
    }

    respond "JA3: {tls.ja3} | JA4: {tls.ja4}"
}
```

### Options

#### `sort_ja3_extensions`

When enabled, TLS extensions are sorted by ID before JA3 computation. This normalizes fingerprints across clients that randomize extension order.

```caddyfile
example.com {
    ja3_ja4 {
        sort_ja3_extensions
    }

    respond "Sorted JA3: {tls.ja3}"
}
```

> **Warning:** Enabling this may increase false positives because some legitimate tools (curl, browsers) may produce the same JA3 hash as bots that randomize extensions.

### JSON Configuration

```json
{
  "apps": {
    "tls": {
      "certificates": {
        "automate": ["example.com"]
      }
    },
    "http": {
      "servers": {
        "srv0": {
          "routes": [
            {
              "handle": [
                {
                  "handler": "ja3_ja4"
                },
                {
                  "handler": "static_response",
                  "body": "JA3: {tls.ja3} | JA4: {tls.ja4}"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

## Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{tls.ja3}` | JA3 MD5 hash (32 hex chars) | `a0e9f5d64349fb13191bc781b58dbe36` |
| `{tls.ja3_raw}` | Raw JA3 string before hashing | `771,4865-4866,0-23-65281,29-23-24,0` |
| `{tls.ja4}` | JA4 structured fingerprint | `t13d1516h2_8daaf6152771_02705d924276` |
| `{tls.ja3_sorted}` | Whether extensions were sorted | `true` or `false` |

## Usage Examples

### Log Fingerprints

```caddyfile
example.com {
    ja3_ja4

    log {
        output file /var/log/caddy/access.log
        format json
    }

    respond "OK"
}
```

### Route Based on Fingerprint

```caddyfile
example.com {
    ja3_ja4

    @known_browser expression {tls.ja3} == 'a0e9f5d64349fb13191bc781b58dbe36'
    handle @known_browser {
        respond "Welcome back!"
    }
}
```

### Pass Fingerprint to Upstream

```caddyfile
api.example.com {
    ja3_ja4

    reverse_proxy localhost:8080 {
        header_up X-Client-JA3 {tls.ja3}
        header_up X-Client-JA4 {tls.ja4}
    }
}
```

## Development

### Prerequisites

- Go 1.25+
- Make
- Docker / Docker Compose (optional, for testing)

### Quick Start

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Generate test coverage
make test-coverage

# Lint the codebase
make lint

# Build with xcaddy
make xcaddy

# Start local test environment with Docker Compose
make docker-up
```

### Project Structure

```
.
├── cmd/caddy/main.go        # Standalone binary entry point
├── ja3ja4.go                # Module registration, Provision, Caddyfile parsing
├── fingerprints.go          # JA3/JA4 computation + FingerprintStore
├── fingerprints_test.go     # Unit tests for fingerprint computation
├── context_module.go        # tls.context.ja3ja4 HandshakeContext module
├── handler.go               # HTTP middleware: ServeHTTP + ConnContext
├── integration_test.go      # Integration tests
├── go.mod
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Local test environment
└── README.md
```

## Architecture

### How It Works

1. **Provision Phase**: When the `ja3_ja4` handler is provisioned, it:
   - Gets the current `*caddyhttp.Server` from context
   - Injects `{"module": "ja3ja4"}` into every `TLSConnPolicy.HandshakeContextRaw`
   - Registers a `ConnContext` callback to store `net.Conn` in request context

2. **TLS Handshake Phase**: When a client connects:
   - Caddy invokes `HandshakeContextModule.HandshakeContext(hello)`
   - JA3 is computed in pure Go (version, ciphers, extensions, curves, point formats)
   - JA4 is computed via `github.com/exaring/ja4plus`
   - Fingerprints are stored in a `sync.Mutex`-protected map keyed by `conn.RemoteAddr()`

3. **HTTP Request Phase**: When the request reaches the handler:
   - The `net.Conn` is retrieved from request context (via `ConnContext`)
   - The fingerprint is looked up in the store
   - Placeholders are set on the replacer: `{tls.ja3}`, `{tls.ja4}`, etc.

### Why This Design?

- **No global side effects**: Fingerprints are per-connection, not per-module
- **Compatible with Caddy 2.11+**: Uses the `tls.context` HandshakeContext mechanism
- **Thread-safe**: Uses `sync.Mutex` for the fingerprint store
- **Graceful cleanup**: Connections are automatically removed from the store

## Known Limitations

### JA3 Version Field

Go's `crypto/tls` does not expose the raw `ClientHello.client_version` field.
This module uses `SupportedVersions[0]` instead. For TLS 1.3 clients this
yields `0x0304` (TLS 1.3) rather than the legacy `0x0303` value that reference
implementations such as Wireshark/tshark emit, so **JA3 hashes will differ for
TLS 1.3 clients**.

### GREASE Filtering

GREASE values (RFC 8701: `0x?A?A` pattern) are filtered from cipher suites,
extensions, and elliptic curves before hashing, matching the canonical JA3
specification. If you compare against fingerprints generated by a tool that does
*not* filter GREASE, the hashes will differ.

## Security Considerations

- JA3/JA4 are **passive fingerprints** -- they do not modify TLS traffic
- Fingerprints **can be spoofed** by custom TLS implementations or MITM proxies
- **Never use as a sole authentication mechanism**
- Recommended use cases: bot detection, threat intelligence, rate-limiting, analytics

## References

- [JA3 Specification (Salesforce)](https://github.com/salesforce/ja3)
- [JA4+ Specification (FoxIO)](https://github.com/FoxIO-LLC/ja4)
- [exaring/ja4plus](https://github.com/exaring/ja4plus) -- JA4 implementation library

## License

MIT License. See [LICENSE](LICENSE) for details.
