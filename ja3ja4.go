package ja3ja4

import (
	"encoding/json"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JA3JA4{})
	httpcaddyfile.RegisterHandlerDirective("ja3_ja4", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ja3_ja4", "before", "header")
}

// matcherName is the tls.handshake_match module that records fingerprints.
const matcherName = "ja3ja4"

// JA3JA4 is a Caddy HTTP module that computes JA3 and JA4 TLS fingerprints
// and exposes them as request placeholders.
type JA3JA4 struct {
	// SortJA3Extensions sorts TLS extensions, elliptic curves, and point
	// formats by numeric ID before JA3 computation. This normalises
	// fingerprints for clients that randomise extension order, mitigating
	// one common evasion technique, but may increase false positives because
	// legitimate tools (curl, browsers) may then collide with bots.
	// Default: false (preserve wire order per the JA3 specification).
	SortJA3Extensions bool `json:"sort_ja3_extensions,omitempty"`

	logger   *zap.Logger
	sweeping bool // whether Provision acquired the shared sweeper
}

// CaddyModule returns module info.
func (JA3JA4) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja3_ja4",
		New: func() caddy.Module { return new(JA3JA4) },
	}
}

// Provision sets up the module. It also installs the JA3/JA4 handshake matcher
// in all TLS connection policies for the current server, and registers
// ConnContext/ConnState callbacks so the underlying net.Conn is available in
// requests and its fingerprint is dropped when it closes.
func (m *JA3JA4) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	srvIface := ctx.Value(caddyhttp.ServerCtxKey)
	if srvIface == nil {
		m.logger.Warn("no server found in context; fingerprinting may not work")
		return nil
	}

	srv, ok := srvIface.(*caddyhttp.Server)
	if !ok {
		m.logger.Warn("server in context is not *caddyhttp.Server; fingerprinting may not work")
		return nil
	}

	if err := installMatcher(srv.TLSConnPolicies, m.SortJA3Extensions, m.logger); err != nil {
		return err
	}

	srv.RegisterConnContext(connContextFunc)
	srv.RegisterConnState(connStateFunc)

	store.EnsureTTL(ttlForIdleTimeout(time.Duration(srv.IdleTimeout)))
	store.AcquireSweeper()
	m.sweeping = true

	return nil
}

// installMatcher records fingerprints from a connection-policy matcher: unlike
// the handshake context hook it runs for every ClientHello, including TLS 1.3
// resumptions that never select a certificate.
//
// The first handler to provision on a server wins: an existing matcher is never
// replaced. Handlers cannot be tied to individual policies (a policy is picked
// by SNI before any route runs), so the sort setting is effectively
// server-wide, and a later handler asking for a different one gets a warning.
// {tls.ja3_sorted} always reports what was really used.
func installMatcher(policies caddytls.ConnectionPolicies, sortExtensions bool, logger *zap.Logger) error {
	if len(policies) == 0 {
		logger.Warn("this server has no TLS connection policies (plain HTTP?); " +
			"ja3_ja4 has no handshake to fingerprint, so {tls.ja3} and {tls.ja4} will be empty")
		return nil
	}

	matcherJSON, err := json.Marshal(HandshakeMatcher{SortJA3Extensions: sortExtensions})
	if err != nil {
		return err
	}

	for _, cp := range policies {
		if cp.MatchersRaw == nil {
			cp.MatchersRaw = make(caddy.ModuleMap)
		}
		existing, exists := cp.MatchersRaw[matcherName]
		if !exists {
			cp.MatchersRaw[matcherName] = matcherJSON
			continue
		}

		var installed HandshakeMatcher
		if err := json.Unmarshal(existing, &installed); err == nil && installed.SortJA3Extensions != sortExtensions {
			logger.Warn("another ja3_ja4 handler on this server already set sort_ja3_extensions differently; "+
				"the first one wins for every site on the server, {tls.ja3_sorted} reports what is actually used",
				zap.Bool("in_effect", installed.SortJA3Extensions),
				zap.Bool("ignored", sortExtensions))
			return nil // identical for every remaining policy
		}
	}
	return nil
}

// Cleanup releases the shared background sweeper; it stops once the last
// handler instance is cleaned up.
func (m *JA3JA4) Cleanup() error {
	if m.sweeping {
		m.sweeping = false
		store.ReleaseSweeper()
	}
	return nil
}

// Validate ensures the module configuration is valid.
func (m *JA3JA4) Validate() error {
	return nil
}

// UnmarshalCaddyfile sets up from Caddyfile.
func (m *JA3JA4) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "sort_ja3_extensions":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.SortJA3Extensions = true
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(JA3JA4)
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

// Interface compliance checks.
var (
	_ caddy.Module                = (*JA3JA4)(nil)
	_ caddy.Provisioner           = (*JA3JA4)(nil)
	_ caddy.CleanerUpper          = (*JA3JA4)(nil)
	_ caddy.Validator             = (*JA3JA4)(nil)
	_ caddyhttp.MiddlewareHandler = (*JA3JA4)(nil)
	_ caddyfile.Unmarshaler       = (*JA3JA4)(nil)
)
