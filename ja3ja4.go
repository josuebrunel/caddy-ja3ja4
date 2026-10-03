package ja3ja4

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
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

// serverHooks makes sure the ConnContext/ConnState callbacks are registered
// once per server, however many ja3_ja4 handlers it has. Without it every
// handler instance would append its own copy, and each connection would run N
// identical callbacks.
type serverHooks struct {
	mu            sync.Mutex
	refs          map[*caddyhttp.Server]int
	registrations int // how many times hooks were really registered (for tests)
}

var hooks = &serverHooks{refs: make(map[*caddyhttp.Server]int)}

// acquire registers the hooks on srv the first time it is called for it.
func (h *serverHooks) acquire(srv *caddyhttp.Server) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refs[srv] == 0 {
		srv.RegisterConnContext(connContextFunc)
		srv.RegisterConnState(connStateFunc)
		h.registrations++
	}
	h.refs[srv]++
}

// release forgets srv once its last handler is cleaned up, so reloaded configs
// (which build new Server values) don't accumulate stale entries. Caddy has no
// way to unregister the callbacks; they die with the old Server.
func (h *serverHooks) release(srv *caddyhttp.Server) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refs[srv] <= 1 {
		delete(h.refs, srv)
		return
	}
	h.refs[srv]--
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

	// MaxEntries is how many connections' fingerprints the store may hold at
	// once (QUIC connections may use at most half of that). Once it is full,
	// new connections get no fingerprint until entries are freed. The store is
	// shared by every server in the process and fits the largest value any
	// handler asks for.
	// Default: 100000.
	MaxEntries int `json:"max_entries,omitempty"`

	logger   *zap.Logger
	sweeping bool              // whether Provision acquired the shared sweeper
	srv      *caddyhttp.Server // server whose hooks Provision acquired
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

	hooks.acquire(srv)
	m.srv = srv

	store.EnsureTTL(ttlForIdleTimeout(time.Duration(srv.IdleTimeout)))
	if m.MaxEntries > 0 {
		store.EnsureMax(m.MaxEntries)
	}
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

// Cleanup releases the server hooks and the shared background sweeper; the
// sweeper stops once the last handler instance is cleaned up.
func (m *JA3JA4) Cleanup() error {
	if m.srv != nil {
		hooks.release(m.srv)
		m.srv = nil
	}
	if m.sweeping {
		m.sweeping = false
		store.ReleaseSweeper()
	}
	return nil
}

// Validate ensures the module configuration is valid.
func (m *JA3JA4) Validate() error {
	if m.MaxEntries < 0 {
		return fmt.Errorf("max_entries must not be negative, got %d", m.MaxEntries)
	}
	return nil
}

// UnmarshalCaddyfile sets up from Caddyfile.
func (m *JA3JA4) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	opts, err := parseOptions(d)
	if err != nil {
		return err
	}
	m.SortJA3Extensions = opts.sortExtensions
	m.MaxEntries = opts.maxEntries
	return nil
}

// options are the settings a ja3_ja4 directive block can carry.
type options struct {
	sortExtensions bool
	maxEntries     int // 0 when not set
}

// parseOptions parses the directive block shared by the handler and the TLS
// context module:
//
//	ja3_ja4 {
//		sort_ja3_extensions
//		max_entries <n>
//	}
func parseOptions(d *caddyfile.Dispenser) (options, error) {
	var opts options
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "sort_ja3_extensions":
				if d.NextArg() {
					return options{}, d.ArgErr()
				}
				opts.sortExtensions = true
			case "max_entries":
				if opts.maxEntries != 0 {
					return options{}, d.Err("max_entries specified more than once")
				}
				if !d.NextArg() {
					return options{}, d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil || n <= 0 {
					return options{}, d.Errf("max_entries must be a positive integer, got %q", d.Val())
				}
				if d.NextArg() {
					return options{}, d.ArgErr()
				}
				opts.maxEntries = n
			default:
				return options{}, d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return opts, nil
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
