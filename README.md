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

When enabled, TLS extensions, curves and point formats are sorted by ID in the JA3 this handler reports. This normalizes fingerprints across clients that randomize extension order. The setting is per `ja3_ja4` handler, so sites on the same server can differ; `{tls.ja3_sorted}` tells you which variant a request got. (The `sort_ja3_extensions` field of the `tls.handshake_match.ja3ja4` and `tls.context.ja3ja4` modules is deprecated and ignored.)

```caddyfile
example.com {
    ja3_ja4 {
        sort_ja3_extensions
    }

    respond "Sorted JA3: {tls.ja3}"
}
```

> **Warning:** Enabling this may increase false positives because some legitimate tools (curl, browsers) may produce the same JA3 hash as bots that randomize extensions.

#### `max_entries`

How many connections' fingerprints the store may hold at once (default `100000`). QUIC (HTTP/3) connections may use at most half of it, so a flood of QUIC handshakes can't leave TCP clients without a fingerprint. Once the store is full, new connections get empty placeholders until entries are freed, and a rate-limited warning is logged.

```caddyfile
example.com {
    ja3_ja4 {
        max_entries 250000
    }
}
```

The store is shared by every server in the process: it grows to the largest `max_entries` any handler asks for and never shrinks. In JSON it is the `max_entries` field of the `ja3_ja4` handler.

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

### Try It With Docker Compose

```bash
make generate-certs    # self-signed cert for localhost, once
make docker-test       # build, start, send test requests, show what was logged
```

`make docker-test` starts Caddy with `Caddyfile.test` on `https://localhost:8443`, runs a small curl client that connects with different HTTP and TLS versions (and a custom User-Agent), then prints one compact line per request:

```json
{"time":"13:45:14","client":"172.27.0.3","proto":"HTTP/2.0","tls":772,"ja3":"b4033f0c...","ja4":"t13d0311h2_55b375c5d22e_19b07b4d796e","sorted":"false","ua":"curl/8.22.0","status":200}
```

To test with a browser or your own client, open `https://localhost:8443` (accept the self-signed certificate) and watch the same view live:

```bash
make docker-logs       # follow the access log, one line per request (needs jq)
make docker-logs-raw   # Caddy's complete, unfiltered output
make docker-down
```

The fingerprints reach the log through `log_append` lines in `Caddyfile.test`, and the one-line view comes from `scripts/access-log.jq`. Times are UTC.

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
├── scripts/                 # access-log.jq (log view), test-requests.sh (compose client)
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Local test environment
└── README.md
```

## Architecture

### How It Works

1. **Provision Phase**: When a `ja3_ja4` handler is provisioned, it:
   - Gets the current `*caddyhttp.Server` from context
   - Adds a `tls.handshake_match.ja3ja4` matcher to every TLS connection policy of that server
   - Registers `ConnContext` and `ConnState` callbacks, once per server
   - Joins the shared background sweeper, sizes the store TTL from the server's idle timeout, and raises the store capacity if `max_entries` asks for more

2. **TLS Handshake Phase**: For every ClientHello, including resumed TLS 1.3 sessions and QUIC handshakes, Caddy evaluates the connection policies' matchers:
   - The matcher computes JA3 in pure Go (always in wire order) and JA4 through `github.com/exaring/ja4plus`
   - The result is stored in a sharded, lock-protected map keyed by the connection's transport (TCP or QUIC) and remote address
   - The matcher always returns true, so it never changes which policy is selected

3. **HTTP Request Phase**: When the request reaches the handler:
   - The `net.Conn` is taken from the request context (set by `ConnContext`), or the request's remote address is used for HTTP/3
   - The fingerprint is looked up in the store; a handler with `sort_ja3_extensions` derives the sorted JA3 from it (once per connection, then cached)
   - Placeholders are set on the replacer: `{tls.ja3}`, `{tls.ja4}`, etc. (empty if nothing was found)

4. **Cleanup**:
   - **TCP**: when Caddy reports the connection closed (or hijacked), `ConnState` deletes its entry.
   - **QUIC**: there is no close event to hook, so the sweeper expires entries instead: one minute after the handshake if no request ever used it, otherwise once it has been idle for the server's idle timeout plus a minute.

### Why This Design?

- **A matcher, not the handshake context**: Caddy's `HandshakeContext` hook only runs while a certificate is being selected, which resumed TLS 1.3 sessions skip. Connection-policy matchers run for every ClientHello. (`tls.context.ja3ja4` is still registered so existing JSON configs that reference it keep working, but the handler no longer installs it.)
- **Per-connection, not per-module**: Fingerprints are keyed by connection, not tied to a single handler instance
- **Wire order in the store, sorting at the edge**: Sorting only reorders three fields of the JA3 string, so the store keeps one variant and each handler derives the one it wants. That is what makes `sort_ja3_extensions` a per-handler setting even though the TLS layer is shared by every site on a port
- **Bounded memory**: Entries are removed when their TCP connection closes, QUIC entries expire as described above, and the store holds at most `max_entries` entries (100,000 by default; new ones are dropped, with a rate-limited warning, once it is full). QUIC may use at most half of that, so a flood of QUIC handshakes can't leave TCP clients without a fingerprint. Every lookup, and every transition to idle, refreshes an entry, so live keep-alive connections are never evicted
- **No global lock**: The store is split into 32 shards, so handshakes, request lookups and the sweeper rarely contend

## Known Limitations

### Every handshake on the server is fingerprinted

The matcher is installed in every TLS connection policy of a Caddy server, i.e. every site sharing a listening port, as soon as one of them uses `ja3_ja4`. Handlers can't be tied to individual policies, because a policy is chosen from the ClientHello before any route runs. So the handshakes of sites that don't use `ja3_ja4` are fingerprinted too (about 4 microseconds each). Only the placeholders and `sort_ja3_extensions` are per handler.

### HTTP/3 connections are expired, not deleted

Caddy gives modules a hook for TCP connections closing but has none for QUIC (tracked in [#41](https://github.com/josuebrunel/caddy-ja3ja4/issues/41)). Until it does, QUIC entries are removed by the sweeper, which has three consequences:

- **A QUIC connection whose first request comes more than a minute after its handshake has no fingerprint.** Placeholders are empty for it. This can happen with a browser's speculative preconnect; an HTTP/3 client that connects to send a request does so within moments.
- **Closed QUIC connections' entries linger** until they expire (up to the idle timeout plus a minute), so how many fit depends on how many new HTTP/3 connections arrive per second.
- **Unanswered handshakes create entries.** quic-go processes a QUIC Initial's ClientHello before the client's address is verified, and Caddy only demands verification above 1000 handshakes per second, so spoofed-source packets can create entries. They are bounded by the QUIC share of the store and expire after a minute, and TCP connections always keep at least half of the store's capacity.

### The store is capped

At most `max_entries` connections are tracked at once (100,000 by default), and QUIC may use half of that. Beyond that, fingerprints for new connections are dropped until space frees up, their placeholders are empty, and a warning naming the budget that is full is logged at most once a minute.

## Compatibility Notes

These are behaviours worth knowing about when comparing with other tools, not shortcomings.

- **GREASE filtering.** GREASE values (RFC 8701: `0x?A?A` pattern) are filtered from the version, cipher suites, extensions and elliptic curves before hashing, as the JA3 specification requires. If you compare against fingerprints generated by a tool that does *not* filter GREASE, the hashes will differ.
- **JA3 version field.** Go's `crypto/tls` doesn't expose the raw `client_version` field, so the module reconstructs it: `771` (`0x0303`) whenever the client sent the `supported_versions` extension, which RFC 8446 requires, and otherwise the first non-GREASE version Go reports. For compliant clients this matches Wireshark/tshark and other reference tools.
- **JA4 transport.** The JA4 starts with `t` for TCP and `q` for QUIC (HTTP/3).
- **`sort_ja3_extensions` is a handler setting.** The `sort_ja3_extensions` field of the `tls.handshake_match.ja3ja4` and `tls.context.ja3ja4` modules is deprecated and ignored. If a JSON config set it there, set it on the `ja3_ja4` handler instead, or `{tls.ja3}` will now be the wire-order hash.

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
