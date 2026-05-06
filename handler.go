package ja3ja4

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ServeHTTP implements the middleware handler.
func (m *JA3JA4) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract fingerprints from context if present
	if fp, ok := r.Context().Value(fpContextKey{}).(tlsFingerprint); ok {
		repl := r.Context().Value(caddyhttp.ReplacerCtxKey).(*caddy.Replacer)
		if repl != nil {
			repl.Set("tls.ja3", fp.JA3)
			repl.Set("tls.ja4", fp.JA4)
		}
	}
	return next.ServeHTTP(w, r)
}
