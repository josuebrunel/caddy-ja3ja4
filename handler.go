package ja3ja4

import (
	"context"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type connCtxKey struct{}
type fpCtxKey struct{}

// ServeHTTP implements the middleware handler. It retrieves the net.Conn
// from the request context, looks up the JA3/JA4 fingerprint in the
// global store, and sets placeholders on the replacer.
//
// The lookup order is:
//  1. TLSFingerprint embedded directly in the request context (via HandshakeContext callback)
//  2. net.Conn value in the request context → global store lookup by remote address
//  3. RemoteAddr from the request → global store lookup by remote address (HTTP/3 fallback)
func (m *JA3JA4) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey)
	if repl == nil {
		return next.ServeHTTP(w, r)
	}
	rp, ok := repl.(*caddy.Replacer)
	if !ok {
		return next.ServeHTTP(w, r)
	}

	var fp TLSFingerprint
	var found bool

	// 1. Check if the fingerprint was embedded directly in the context by HandshakeContext.
	if fp, found = r.Context().Value(fpCtxKey{}).(TLSFingerprint); !found {
		// 2. Fallback to looking up in the global store via the net.Conn from the request context.
		if conn, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok {
			fp, found = store.Load(conn)
		}
	}

	if !found {
		// 3. Fallback for HTTP/3 where the net.Conn is not available in the request context.
		// Use the remote address from the request to look up the fingerprint.
		fp, found = store.LoadByRemoteAddr(r.RemoteAddr)
	}

	if found {
		rp.Set("tls.ja3", fp.JA3)
		rp.Set("tls.ja4", fp.JA4)
		rp.Set("tls.ja3_raw", fp.JA3Raw)

		if m.SortJA3Extensions {
			rp.Set("tls.ja3_sorted", "true")
		} else {
			rp.Set("tls.ja3_sorted", "false")
		}
	}

	return next.ServeHTTP(w, r)
}

// connContextFunc is registered via Server.RegisterConnContext during
// Provision. It stores the net.Conn in the request context so that
// ServeHTTP can look up the associated fingerprint.
//
// NOTE: We do NOT register a cleanup callback here because in Caddy's
// connection handling, the context passed to this function may be
// cancelled after individual requests on keep-alive connections, not
// just when the TCP connection itself closes. Registering a cleanup
// via context.AfterFunc would prematurely delete the fingerprint from
// the store, causing {tls.ja3} / {tls.ja4} placeholders to appear
// unsubstituted on subsequent requests on the same keep-alive connection.
//
// Instead, the global FingerprintStore uses a sliding TTL: every lookup
// refreshes the entry's last-seen timestamp, and a background sweeper
// (started in JA3JA4.Provision via FingerprintStore.StartSweeper) reclaims
// entries that go unused past that TTL. This bounds memory usage without
// ever evicting a fingerprint that's still actively in use.
func connContextFunc(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connCtxKey{}, c)
}
