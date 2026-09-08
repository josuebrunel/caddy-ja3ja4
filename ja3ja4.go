package ja3ja4

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JA3JA4{})
	httpcaddyfile.RegisterHandlerDirective("ja3_ja4", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ja3_ja4", "before", "header")
}

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

	logger *zap.Logger
}

// CaddyModule returns module info.
func (JA3JA4) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja3_ja4",
		New: func() caddy.Module { return new(JA3JA4) },
	}
}

// Provision sets up the module. It also injects the JA3/JA4 handshake context
// into all TLS connection policies for the current server, and registers a
// ConnContext callback so the underlying net.Conn is available in requests.
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

	hcJSON, err := json.Marshal(map[string]any{
		"module":              "ja3ja4",
		"sort_ja3_extensions": m.SortJA3Extensions,
	})
	if err != nil {
		return err
	}

	for _, cp := range srv.TLSConnPolicies {
		// Only inject if nothing else has already claimed the handshake context
		// slot; overwriting another module's config would silently break it.
		if cp.HandshakeContextRaw == nil {
			cp.HandshakeContextRaw = hcJSON
		}
	}

	srv.RegisterConnContext(connContextFunc)

	store.StartSweeper(ctx.Context)

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
	_ caddy.Validator             = (*JA3JA4)(nil)
	_ caddyhttp.MiddlewareHandler = (*JA3JA4)(nil)
	_ caddyfile.Unmarshaler       = (*JA3JA4)(nil)
)
