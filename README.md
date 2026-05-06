# caddy-ja3ja4

[![CI](https://github.com/yourorg/caddy-ja3ja4/actions/workflows/ci.yml/badge.svg)](https://github.com/yourorg/caddy-ja3ja4/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yourorg/caddy-ja3ja4.svg)](https://pkg.go.dev/github.com/yourorg/caddy-ja3ja4)

A production-ready Caddy v2 module for TLS fingerprinting using [JA3](https://github.com/salesforce/ja3) and [JA4+](https://github.com/FoxIO-LLC/ja4).

## ✨ Features

- ✅ Compute **JA3** (MD5 hash of ClientHello) and **JA4** (structured fingerprint)
- ✅ Expose fingerprints via Caddy placeholders: `{tls.ja3}`, `{tls.ja4}`
- ✅ Zero global side effects: preserves TLS session resumption
- ✅ Context-safe: per-request fingerprint storage
- ✅ Graceful degradation: handles non-TLS, HTTP/3, and parsing errors
- ✅ Actively maintained dependencies

## 🚀 Installation

### Option 1: Build with xcaddy (Recommended)

```bash
# Install xcaddy
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Build Caddy with plugin
xcaddy build \
  --with github.com/yourorg/caddy-ja3ja4@latest \
  --output ./caddy
```


### Option 2: Build from source

```bash
git clone https://github.com/yourorg/caddy-ja3ja4
cd caddy-ja3ja4
make xcaddy
```

## Configuration

### Caddyfile

```caddyfile
{
	order ja3_ja4 first
}

example.com {
	# Enable fingerprinting in TLS config
	tls {
		ja3ja4
	}

	# Add middleware to expose placeholders
	ja3_ja4

	# Use fingerprints for logging
	log {
		output file /var/log/caddy/access.log
		format json
	}

	# Conditional routing based on fingerprint
	@suspicious expression {tls.ja4} != "" && {tls.ja4} != "n/a" && {tls.ja4} != "error"
	handle @suspicious {
		# Log fingerprint for analysis
		log "Suspicious client JA4: {tls.ja4}"
		# Optional: add header for upstream
		header_up X-Client-JA4 {tls.ja4}
	}

	respond "Hello, {tls.ja3}!"
}
```

### JSON config

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "routes": [
            {
              "handle": [
                {
                  "handler": "ja3_ja4"
                }
              ]
            }
          ]
        }
      }
    },
    "tls": {
      "certificates": {
        "automate": ["example.com"]
      },
      "connection_policies": [
        {
          "protocol_preferences": ["tls1.2", "tls1.3"],
          "ja3ja4": {}
        }
      ]
    }
  }
}
```

## Placeholder reference

| Placeholder | Description               | Example                                      |
|------------|---------------------------|----------------------------------------------|
| {tls.ja3}  | JA3 MD5 hash              | a0e9f5d64349fb13191bc781b58dbe36             |
| {tls.ja4}  | JA4 structured fingerprint | t13d1516h2_8daaf6152771_02705d924276         |

## Testing

```bash
# Generate test certificates
make generate-certs

# Run all tests
make test

# Run integration tests only
make test-integration
```

## Security Considerations

* JA3/JA4 are passive fingerprints; they do not modify traffic.
* Fingerprints can be spoofed by custom TLS implementations.
* Never use as sole authentication mechanism.
* Recommended for: bot detection, threat intelligence, rate-limiting, analytics

