# caddy-ja3ja4

[![Go Reference](https://pkg.go.dev/badge/github.com/josuebrunel/caddy-ja3ja4.svg)](https://pkg.go.dev/github.com/josuebrunel/caddy-ja3ja4)
[![CI](https://github.com/josuebrunel/caddy-ja3ja4/actions/workflows/ci.yml/badge.svg)](https://github.com/josuebrunel/caddy-ja3ja4/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/josuebrunel/caddy-ja3ja4)](https://goreportcard.com/report/github.com/josuebrunel/caddy-ja3ja4)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Caddy v2 module for TLS fingerprinting using [JA3](https://github.com/salesforce/ja3) and [JA4+](https://github.com/FoxIO-LLC/ja4).

## Features

- **JA3 Fingerprinting** -- MD5 hash of the TLS ClientHello parameters (version, ciphers, extensions, curves, point formats), with GREASE filtered out as the spec requires and the version field reconstructed to match reference implementations
- **JA4 Fingerprinting** -- JA4 via the `github.com/exaring/ja4plus` library, correctly labelled `t` (TCP) or `q` (QUIC / HTTP/3)
- **Placeholder Integration** -- Expose fingerprints as `{tls.ja3}`, `{tls.ja4}`, `{tls.ja3_raw}`, and `{tls.ja3_sorted}` for use in logging, routing, headers, and matchers
- **Resumed Sessions and HTTP/3** -- Fingerprints are recorded on every ClientHello, so TLS 1.3 session resumption and HTTP/3 connections are covered, not just full TCP handshakes
- **Bounded Fingerprint Store** -- Entries are dropped when their connection closes, the store is capped, and a shared background sweeper reclaims anything left behind, so long-running servers don't leak memory and handshake floods can't grow it without limit
- **Extension Sorting** -- Optional `sort_ja3_extensions` flag to counter extension-randomization evasion techniques
- **Predictable Degradation** -- Requests without a fingerprint (plain HTTP, a full store) get empty placeholders rather than literal `{tls.ja3}` text
- **Caddy 2.11+ Compatible** -- Hooks in through a `tls.handshake_match` module; no TLS configuration is needed

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

The plugin is configured entirely through the HTTP handler. No TLS block and no global `order` option are needed: the directive registers itself to run before `header`, so the placeholders are available to `header`, `reverse_proxy`, `respond` and `log_append`.

```caddyfile
example.com {
    ja3_ja4

    respond "JA3: {tls.ja3} | JA4: {tls.ja4}"
}
```

Fingerprints are recorded for every TLS connection on a Caddy server, i.e. all sites sharing a listening port, as soon as one of them uses `ja3_ja4`, including resumed TLS 1.3 sessions and HTTP/3. Requests without a fingerprint, such as plain HTTP, get empty placeholders.

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
| `{tls.ja3_sorted}` | Whether this fingerprint's JA3 was computed with sorting | `true` or `false` |

All four are empty for a request that has no fingerprint, such as plain HTTP.

## Usage Examples

### Log Fingerprints

Caddy's access log doesn't know about custom placeholders, so add them with
[`log_append`](https://caddyserver.com/docs/caddyfile/directives/log_append):

```caddyfile
example.com {
    ja3_ja4

    log {
        output file /var/log/caddy/access.log
        format json
    }
    log_append ja3 {tls.ja3}
    log_append ja4 {tls.ja4}

    respond "OK"
}
```

Each access-log line then carries `"ja3": "..."` and `"ja4": "..."`.

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

# Check for known vulnerabilities in dependencies
make vulncheck

# Benchmarks, and a short fuzz session on the JA3 builder
make bench
make fuzz FUZZTIME=30s

# Check go.mod is tidy (what CI runs)
make mod-check

# Build with xcaddy
make xcaddy

# Start local test environment with Docker Compose
make docker-up
```

### Project Structure

```
.
├── cmd/caddy/main.go        # Standalone binary entry point
├── ja3ja4.go                # ja3_ja4 handler: Provision/Cleanup, matcher installation, Caddyfile parsing
├── handler.go               # ServeHTTP, plus the ConnContext/ConnState hooks
├── context_module.go        # tls.handshake_match.ja3ja4 (records fingerprints) and the legacy tls.context.ja3ja4
├── fingerprints.go          # JA3/JA4 computation + the sharded FingerprintStore
├── fingerprints_test.go     # Unit tests (incl. known-answer vectors)
├── e2e_test.go              # End-to-end tests against a real in-process Caddy
├── reference_test.go        # Simple JA3 builder used as an oracle for the optimised one
├── bench_test.go            # Benchmarks
├── helpers_test.go          # Test isolation helpers
├── integration_test.go      # Module provisioning tests
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Local test environment
└── README.md
```

## Architecture

### How It Works

1. **Provision Phase**: When a `ja3_ja4` handler is provisioned, it:
   - Gets the current `*caddyhttp.Server` from context
   - Adds a `tls.handshake_match.ja3ja4` matcher to every TLS connection policy of that server (the first handler's `sort_ja3_extensions` wins, see below)
   - Registers `ConnContext` and `ConnState` callbacks, once per server
   - Joins the shared background sweeper and sizes the store TTL from the server's idle timeout

2. **TLS Handshake Phase**: For every ClientHello, including resumed TLS 1.3 sessions and QUIC handshakes, Caddy evaluates the connection policies' matchers:
   - The matcher computes JA3 in pure Go and JA4 through `github.com/exaring/ja4plus`
   - The result is stored in a sharded, lock-protected map keyed by the connection's remote address
   - The matcher always returns true, so it never changes which policy is selected

3. **HTTP Request Phase**: When the request reaches the handler:
   - The `net.Conn` is taken from the request context (set by `ConnContext`), or the request's remote address is used for HTTP/3
   - The fingerprint is looked up in the store
   - Placeholders are set on the replacer: `{tls.ja3}`, `{tls.ja4}`, etc. (empty if nothing was found)

4. **Cleanup**: When Caddy reports the connection closed (or hijacked), `ConnState` deletes its entry.

### Why This Design?

- **A matcher, not the handshake context**: Caddy's `HandshakeContext` hook only runs while a certificate is being selected, which resumed TLS 1.3 sessions skip. Connection-policy matchers run for every ClientHello. (`tls.context.ja3ja4` is still registered so existing JSON configs that reference it keep working, but the handler no longer installs it.)
- **Per-connection, not per-module**: Fingerprints are keyed by connection, not tied to a single handler instance
- **Bounded memory**: Entries are removed when their connection closes, the store holds at most 100,000 entries (new ones are dropped, with a rate-limited warning, once it is full), and a sweeper drops entries unused for the server's idle timeout plus a minute. Every lookup, and every transition to idle, refreshes an entry, so live keep-alive connections are never evicted
- **No global lock**: The store is split into 32 shards, so handshakes, request lookups and the sweeper rarely contend

## Known Limitations

### Fingerprinting is per server

The matcher is installed in every TLS connection policy of a Caddy server, i.e. every site sharing a listening port, as soon as one of them uses `ja3_ja4`. Handlers can't be tied to individual policies, because a policy is chosen from the ClientHello before any route runs. So `sort_ja3_extensions` is effectively server-wide: the first handler's setting wins and a later handler asking for something different logs a warning. `{tls.ja3_sorted}` always reports what was actually used.

### HTTP/3 entries age out instead of being deleted

`ConnState` only exists for TCP connections, so QUIC connections' entries are removed by the sweeper once they've been unused for the idle timeout plus a minute, not at connection close.

### The store is capped

If more than 100,000 connections are tracked at once (or a flood of handshakes arrives faster than they close), fingerprints for new connections are dropped until space frees up, and their placeholders are empty.

### GREASE Filtering

GREASE values (RFC 8701: `0x?A?A` pattern) are filtered from the version,
cipher suites, extensions, and elliptic curves before hashing, matching the canonical JA3
specification. If you compare against fingerprints generated by a tool that does
*not* filter GREASE, the hashes will differ.

### JA3 Version Field

Go's `crypto/tls` doesn't expose the raw `client_version` field. The module reconstructs it: `771` (`0x0303`) whenever the client sent the `supported_versions` extension, which RFC 8446 requires, and otherwise the first non-GREASE version Go reports. For compliant clients this matches what Wireshark/tshark and other reference tools produce.

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
