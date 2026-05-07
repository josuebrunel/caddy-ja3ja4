package ja3ja4

import (
	"context"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type connCtxKey struct{}

// ServeHTTP implements the middleware handler. It retrieves the net.Conn
// from the request context, looks up the JA3/JA4 fingerprint in the
// global store, and sets placeholders on the replacer.
func (m *JA3JA4) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey)
	if repl == nil {
		return next.ServeHTTP(w, r)
	}
	rp, ok := repl.(*caddy.Replacer)
	if !ok {
		return next.ServeHTTP(w, r)
	}

	if conn, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok {
		if fp, found := store.Load(conn); found {
			rp.Set("tls.ja3", fp.JA3)
			rp.Set("tls.ja4", fp.JA4)
			rp.Set("tls.ja3_raw", fp.JA3Raw)

			if m.SortJA3Extensions {
				rp.Set("tls.ja3_sorted", "true")
			} else {
				rp.Set("tls.ja3_sorted", "false")
			}
		}
	}

	return next.ServeHTTP(w, r)
}

// connContextFunc is registered via Server.RegisterConnContext during
// Provision. It stores the net.Conn in the request context so that
// ServeHTTP can look up the associated fingerprint.
func connContextFunc(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connCtxKey{}, c)
}
