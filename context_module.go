package ja3ja4

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(HandshakeContextModule{})
	caddy.RegisterModule(HandshakeMatcher{})
}

// HandshakeMatcher is a tls.handshake_match module that records the JA3/JA4
// fingerprint of every ClientHello and always matches.
//
// Caddy evaluates connection-policy matchers for every ClientHello, including
// TLS 1.3 session resumptions. The HandshakeContext hook, by contrast, only
// runs while a certificate is being selected, which resumed handshakes skip,
// so relying on it left resumed connections without a fingerprint (or with a
// stale one left by an earlier connection from the same address). Recording in
// a matcher also covers HTTP/3, where quic-go sets hello.Conn before the
// policies run.
//
// The matcher has no effect on policy selection. Caddy may call it once per
// policy it tries for a handshake; every call records the same value.
type HandshakeMatcher struct {
	// SortJA3Extensions is ignored. The matcher always records the unsorted
	// fingerprint and each ja3_ja4 handler derives its own sorted variant, so
	// the setting is per handler. The field is kept so existing JSON configs
	// still load.
	//
	// Deprecated: set sort_ja3_extensions on the ja3_ja4 handler instead.
	SortJA3Extensions bool `json:"sort_ja3_extensions,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns module info.
func (HandshakeMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.ja3ja4",
		New: func() caddy.Module { return new(HandshakeMatcher) },
	}
}

// Provision sets up the module.
func (m *HandshakeMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// Match records the fingerprint of hello and reports true.
func (m *HandshakeMatcher) Match(hello *tls.ClientHelloInfo) bool {
	recordFingerprint(hello, m.logger)
	return true
}

// recordFingerprint computes the fingerprints for hello and stores them in the
// global store, keyed by the connection. It returns the fingerprint and whether
// one was computed (false when hello or its connection is missing).
func recordFingerprint(hello *tls.ClientHelloInfo, logger *zap.Logger) (TLSFingerprint, bool) {
	if hello == nil || hello.Conn == nil {
		return TLSFingerprint{}, false
	}

	// Always the unsorted variant: handlers that sort derive it from this.
	ja3Raw, ja3, ja4 := computeFingerprints(hello, false)
	fp := TLSFingerprint{JA3: ja3, JA3Raw: ja3Raw, JA4: ja4}

	if !store.Store(hello.Conn, fp) {
		warnStoreFull(logger, transportOf(hello.Conn.RemoteAddr()))
	}
	return fp, true
}

// HandshakeContextModule implements caddytls.HandshakeContext to compute
// JA3/JA4 fingerprints during the TLS handshake.
//
// The ja3_ja4 handler no longer installs it: that hook is skipped for resumed
// TLS 1.3 sessions, so HandshakeMatcher does the recording instead. It remains
// registered so existing JSON configs that reference tls.context.ja3ja4 keep
// working.
type HandshakeContextModule struct {
	// SortJA3Extensions is ignored; see HandshakeMatcher.SortJA3Extensions.
	//
	// Deprecated: set sort_ja3_extensions on the ja3_ja4 handler instead.
	SortJA3Extensions bool `json:"sort_ja3_extensions,omitempty"`

	logger *zap.Logger
}

// lastStoreFullWarn is the unix-nano time of the last "store full" warning.
// It is package-level because the store it describes is global.
var lastStoreFullWarn atomic.Int64

// CaddyModule returns module info.
func (HandshakeContextModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.context.ja3ja4",
		New: func() caddy.Module { return new(HandshakeContextModule) },
	}
}

// Provision sets up the module.
func (m *HandshakeContextModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// UnmarshalCaddyfile sets up from Caddyfile (for direct use, not via HTTP handler).
func (m *HandshakeContextModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	opts, err := parseOptions(d)
	if err != nil {
		return err
	}
	if opts.maxEntries != 0 {
		return d.Err("max_entries is an option of the ja3_ja4 handler, not of this module")
	}
	m.SortJA3Extensions = opts.sortExtensions
	return nil
}

// HandshakeContext is invoked while Caddy selects a certificate. It records
// the connection's JA3/JA4 fingerprints in the global store, where ServeHTTP
// finds them. It returns the handshake context unchanged: Caddy only hands
// that context to certificate selection, so nothing placed on it would reach
// the request.
func (m *HandshakeContextModule) HandshakeContext(hello *tls.ClientHelloInfo) (context.Context, error) {
	if hello == nil {
		return context.Background(), nil
	}
	recordFingerprint(hello, m.logger)
	return hello.Context(), nil
}

// warnStoreFull logs that a fingerprint was dropped because the store, or the
// QUIC share of it, is full, at most once a minute so a flood cannot also flood
// the log.
func warnStoreFull(logger *zap.Logger, transport Transport) {
	if logger == nil {
		return
	}
	now := time.Now().UnixNano()
	last := lastStoreFullWarn.Load()
	if now-last < int64(time.Minute) || !lastStoreFullWarn.CompareAndSwap(last, now) {
		return
	}
	if transport == TransportQUIC && store.udp.Load() >= store.quicBudget() {
		logger.Warn("QUIC share of the fingerprint store is full; dropping fingerprints for new HTTP/3 connections "+
			"(TCP connections are unaffected)",
			zap.Int64("quic_entries", store.udp.Load()),
			zap.Int64("quic_budget", store.quicBudget()))
		return
	}
	logger.Warn("fingerprint store is full; dropping fingerprints for new connections",
		zap.Int("max_entries", store.Max()))
}

// Interface compliance.
var (
	_ caddy.Module               = (*HandshakeContextModule)(nil)
	_ caddy.Provisioner          = (*HandshakeContextModule)(nil)
	_ caddytls.HandshakeContext  = (*HandshakeContextModule)(nil)
	_ caddytls.ConnectionMatcher = (*HandshakeMatcher)(nil)
	_ caddy.Provisioner          = (*HandshakeMatcher)(nil)
	_ caddyfile.Unmarshaler      = (*HandshakeContextModule)(nil)
)
