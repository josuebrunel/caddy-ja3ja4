// Package ja3ja4 provides a Caddy module for TLS fingerprinting (JA3/JA4).
package ja3ja4

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(JA3JA4{})
	caddytls.RegisterConfigGetter("ja3ja4", getTLSConfig)
	httpcaddyfile.RegisterHandlerDirective("ja3_ja4", parseCaddyfile)
}

// JA3JA4 is the Caddy module for TLS fingerprinting.
type JA3JA4 struct {
	logger *caddy.Logger
}

// CaddyModule returns module info.
func (JA3JA4) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja3_ja4",
		New: func() caddy.Module { return new(JA3JA4) },
	}
}

// Provision sets up the module.
func (m *JA3JA4) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

// Validate ensures the module configuration is valid.
func (m *JA3JA4) Validate() error { return nil }

// UnmarshalCaddyfile sets up from Caddyfile.
func (m *JA3JA4) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// No config options currently supported
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(JA3JA4), nil
}

// Interface compliance
var (
	_ caddy.Module                = (*JA3JA4)(nil)
	_ caddy.Provisioner           = (*JA3JA4)(nil)
	_ caddy.Validator             = (*JA3JA4)(nil)
	_ caddyhttp.MiddlewareHandler = (*JA3JA4)(nil)
	_ caddyfile.Unmarshaler       = (*JA3JA4)(nil)
)
