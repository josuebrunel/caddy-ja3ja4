# Caddy JA3/JA4 Plugin - Implementation Plan (Caddy 2.11)

## Architecture for Caddy 2.11

Caddy 2.11 removed `caddytls.RegisterConfigGetter` and changed several APIs. The new approach:

1. **`tls.context.ja3ja4` module** - Implements `caddytls.HandshakeContext` interface
   - Receives `*tls.ClientHelloInfo` during TLS handshake
   - Computes JA3 (pure Go) and JA4 (via exaring/ja4plus)
   - Stores fingerprint in global `sync.Map` keyed by `uintptr(chi.Conn)`
   - Returns `hello.Context()` unchanged

2. **`http.handlers.ja3_ja4` HTTP middleware** - During Provision:
   - Gets `*Server` from `ctx.Context.Value(ServerCtxKey)`
   - Sets `HandshakeContextRaw = {"module": "ja3ja4"}` on all `srv.TLSConnPolicies`
   - Registers `ConnContext` on the server to inject `net.Conn` into request context
   - In `ServeHTTP`: retrieves connection from context, looks up fingerprint, sets placeholders

3. **Global fingerprint store** - `sync.Map` mapping `uintptr` (conn pointer) to `TLSFingerprint`

### Why this works:
- Handler Provision runs BEFORE `TLSConnPolicies.Provision()` (app.go line 370 vs 396)
- Setting `HandshakeContextRaw` before Provision causes it to be loaded
- `ConnContext` callback fires when connection is accepted, before TLS handshake
- `HandshakeContext` fires during TLS handshake, after connection is accepted
- By the time HTTP request arrives, fingerprint is in the store

### User Configuration

**Caddyfile (no extra TLS config needed):**
```caddyfile
{
    order ja3_ja4 first
}

example.com {
    ja3_ja4
    respond "JA3: {tls.ja3} | JA4: {tls.ja4}"
}
```

**JSON config:**
```json
{
  "apps": {
    "tls": {
      "connection_policies": [{
        "handshake_context": {"module": "ja3ja4"}
      }]
    },
    "http": {
      "servers": {
        "srv0": {
          "routes": [{
            "handle": [{"handler": "ja3_ja4"}]
          }]
        }
      }
    }
  }
}
```

## File Changes

### 1. Remove `test_caddy.go`
Already removed.

### 2. Fix `go.mod`
Change `go 1.25.0` to `go 1.25`.

### 3. Rewrite `ja3ja4.go`
- Remove `caddytls.RegisterConfigGetter` (doesn't exist in 2.11)
- Fix `RegisterDirectiveOrder` to use 3 args: `RegisterDirectiveOrder("ja3_ja4", "before", "header")`
- Keep module registration and handler directive parsing

### 4. Rewrite `fingerprints.go`
- Use `github.com/exaring/ja4plus.JA4(chi)` for JA4
- Keep JA3 computation in pure Go
- Add `TLSFingerprint` struct with `JA3`, `JA3Raw`, `JA4`
- Add `FingerprintStore` with `sync.Map`
- Add `cloneClientHelloWithSortedExtensions`
- Export `GetFingerprintFromContext`

### 5. Rewrite `tls_config.go` → `context_module.go`
- Register as `tls.context.ja3ja4` module
- Implement `caddytls.HandshakeContext` interface
- Compute fingerprints and store in global store
- Return `hello.Context()` unchanged

### 6. Rewrite `handler.go`
- During Provision:
  - Get server from `ServerCtxKey`
  - Inject `HandshakeContextRaw` into connection policies
  - Register `ConnContext` to store connection in request context
- In `ServeHTTP`:
  - Get connection from context
  - Look up fingerprint in global store
  - Set placeholders: `{tls.ja3}`, `{tls.ja4}`, `{tls.ja3_raw}`, `{tls.ja3_sorted}`
- Use `caddy.ReplacerCtxKey` for replacer access

### 7. Clean up `caddyfile.go`
- Remove duplicate `RegisterDirectiveOrder` (already in ja3ja4.go)
- Or keep minimal with just the registration

### 8. Fix `fingerprints_test.go`
- Fix all test assertions
- Add tests for new `FingerprintStore`
- Add test for `cloneClientHelloWithSortedExtensions`
- Use `ja4plus.JA4` for JA4 tests

### 9. Fix `integration_test.go`
- Fix `caddy.Context` creation with `caddy.NewContext()`
- Add tests for Caddyfile parsing
- Add tests for Provision flow

### 10. Add `.gitignore`
### 11. Add `.golangci.yml`
### 12. Add `LICENSE` (MIT)

### 13. Rewrite `README.md`
- Updated for Caddy 2.11 APIs
- Correct installation instructions
- Proper Caddyfile and JSON examples
- Placeholder reference table
- Security considerations

### 14. Update `Makefile`
- Add `fmt`, `vet`, `mod-tidy`, `test-race`, `test-coverage` targets

### 15. Update `.github/workflows/ci.yml`
- Fix test commands
- Add race detection tests

### 16. Add `docker-compose.yml`
- Caddy service with the plugin built via xcaddy
- Volume mount for Caddyfile and test certificates
- Easy testing setup

### 17. Add `Dockerfile`
- Multi-stage build: build Caddy with plugin, then minimal runtime image

## Placeholder Reference

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{tls.ja3}` | JA3 MD5 hash (32 hex chars) | `a0e9f5d64349fb13191bc781b58dbe36` |
| `{tls.ja3_raw}` | Raw JA3 string before hashing | `771,4865-4866,0-23-65281,29-23-24,0` |
| `{tls.ja4}` | JA4 structured fingerprint | `t13d1516h2_8daaf6152771_02705d924276` |
| `{tls.ja3_sorted}` | Whether extensions were sorted | `true` or `false` |
