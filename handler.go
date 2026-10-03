package ja3ja4

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type connCtxKey struct{}

// ServeHTTP implements the middleware handler. It retrieves the net.Conn
// from the request context, looks up the JA3/JA4 fingerprint in the
// global store, and sets placeholders on the replacer (empty when the request
// has no fingerprint).
//
// Fingerprints live in the global store, keyed by the connection's transport
// and remote address (the handshake context Caddy gives modules never reaches
// the request, so there is nothing to read from the request context). The
// lookup order is:
//  1. net.Conn value in the request context (set by connContextFunc) → store lookup
//  2. RemoteAddr from the request → store lookup under the request's transport:
//     QUIC for HTTP/3, where there is no net.Conn, otherwise TCP
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

	// 1. The net.Conn from the request context.
	if conn, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok {
		fp, found = store.Load(conn)
	}

	// 2. HTTP/3 has no net.Conn in the request context, so fall back to the
	// request's remote address. The transport matters: a TCP connection and a
	// QUIC flow may share the same ip:port, and only one of them is this request.
	if !found {
		transport := TransportTCP
		if r.ProtoMajor == 3 {
			transport = TransportQUIC
		}
		fp, found = store.LoadByRemoteAddr(transport, r.RemoteAddr)
	}

	// Always set the placeholders. Caddy leaves unknown placeholders as literal
	// text in header values (e.g. header_up X-JA3 {tls.ja3} would send the
	// string "{tls.ja3}" upstream), so a request without a fingerprint, such as
	// plain HTTP, gets empty values instead.
	sorted := ""
	if found {
		// The store holds the wire-order fingerprint; this handler's own
		// sort_ja3_extensions decides which variant it reports.
		if m.SortJA3Extensions {
			fp = fp.WithSortedJA3()
		}
		sorted = strconv.FormatBool(m.SortJA3Extensions)
	}
	rp.Set("tls.ja3", fp.JA3)
	rp.Set("tls.ja4", fp.JA4)
	rp.Set("tls.ja3_raw", fp.JA3Raw)
	rp.Set("tls.ja3_sorted", sorted)

	return next.ServeHTTP(w, r)
}

// connStateFunc is registered via Server.RegisterConnState during Provision.
// It drops a connection's fingerprint as soon as the connection ends, so the
// store holds roughly one entry per live connection instead of one per
// handshake seen in the last TTL window. net/http reports StateClosed for
// every connection, including ones whose TLS handshake failed, which is why
// this (and not a context callback, see connContextFunc) is the cleanup hook.
func connStateFunc(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		store.Delete(c)
	case http.StateIdle:
		// A request may have run for longer than the TTL; restart the clock now
		// that the connection is waiting for the next one.
		store.Touch(c)
	}
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
// Entries are removed by connStateFunc when the connection closes. As a
// safety net (notably for HTTP/3, which has no ConnState), the global
// FingerprintStore also uses a sliding TTL: every lookup refreshes the
// entry's last-seen timestamp, and a background sweeper (started in
// JA3JA4.Provision via FingerprintStore.StartSweeper) reclaims entries that go
// unused past that TTL, without ever evicting one that's still in use.
func connContextFunc(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connCtxKey{}, c)
}
