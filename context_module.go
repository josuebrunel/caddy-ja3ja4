package ja3ja4

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(HandshakeContextModule{})
}

// HandshakeContextModule implements caddytls.HandshakeContext to compute
// JA3/JA4 fingerprints during the TLS handshake.
type HandshakeContextModule struct {
	SortJA3Extensions bool `json:"sort_ja3_extensions,omitempty"`
}

// CaddyModule returns module info.
func (HandshakeContextModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.context.ja3ja4",
		New: func() caddy.Module { return new(HandshakeContextModule) },
	}
}

// Provision sets up the module.
func (m *HandshakeContextModule) Provision(_ caddy.Context) error {
	return nil
}

// UnmarshalCaddyfile sets up from Caddyfile (for direct use, not via HTTP handler).
func (m *HandshakeContextModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

// HandshakeContext is invoked during the TLS handshake. It computes
// JA3/JA4 fingerprints and embeds them in the returned context so
// that ServeHTTP can retrieve them directly. The fingerprint is also
// stored in the global store as a backup for HTTP/3 and other edge
// cases where context propagation may not reach the request handler.
func (m *HandshakeContextModule) HandshakeContext(hello *tls.ClientHelloInfo) (context.Context, error) {
	if hello == nil || hello.Conn == nil {
		return hello.Context(), nil
	}

	ja3Raw, ja3, ja4 := computeFingerprints(hello, m.SortJA3Extensions)

	fp := TLSFingerprint{
		JA3:    ja3,
		JA3Raw: ja3Raw,
		JA4:    ja4,
	}

	store.Store(hello.Conn, fp)

	ctx := context.WithValue(hello.Context(), fpCtxKey{}, fp)
	return ctx, nil
}

// Interface compliance.
var (
	_ caddy.Module              = (*HandshakeContextModule)(nil)
	_ caddy.Provisioner         = (*HandshakeContextModule)(nil)
	_ caddytls.HandshakeContext = (*HandshakeContextModule)(nil)
	_ caddyfile.Unmarshaler     = (*HandshakeContextModule)(nil)
)
