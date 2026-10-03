package ja3ja4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/quic-go/quic-go/http3"
)

// These tests start a real in-process Caddy with a TLS listener and drive it
// with real TLS clients, so they exercise the whole path: handshake, store,
// ConnState cleanup and placeholder substitution. Caddy is process-global, so
// they must not run in parallel.

// e2eFingerprints is what the test server echoes back for a request.
type e2eFingerprints struct {
	JA3, JA4, JA3Raw, Sorted string
	HeaderJA3                string // X-JA3 response header, set via the header directive
}

func (f e2eFingerprints) empty() bool {
	return f.JA3 == "" && f.JA4 == "" && f.JA3Raw == "" && f.HeaderJA3 == ""
}

type e2eServer struct {
	port int
	url  string
}

// startCaddy loads a Caddy config with a single TLS site on a free port and
// stops it when the test ends. siteBody is the Caddyfile site block body
// (after the tls line); it defaults to the ja3_ja4 directive plus an echo.
func startCaddy(t *testing.T, siteBody string, globalOpts ...string) *e2eServer {
	t.Helper()

	// Keep Caddy's state out of the developer's home directory.
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	certPath, keyPath := writeSelfSignedCert(t, dir)
	port := freePort(t)

	if siteBody == "" {
		siteBody = `
		ja3_ja4
		header X-JA3 {tls.ja3}
		respond "{tls.ja3}|{tls.ja4}|{tls.ja3_raw}|{tls.ja3_sorted}"`
	}
	caddyfile := fmt.Sprintf(`{
	admin off
	auto_https off
	skip_install_trust
	%s
}
localhost:%d {
	bind 127.0.0.1
	tls %s %s
	%s
}
`, strings.Join(globalOpts, "\n\t"), port, certPath, keyPath, siteBody)

	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter not registered")
	}
	cfg, _, err := adapter.Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatalf("loading Caddy config: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Errorf("stopping Caddy: %v", err)
		}
	})

	return &e2eServer{port: port, url: fmt.Sprintf("https://localhost:%d/", port)}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// e2eClient builds a client that dials the test server on loopback and does
// not verify its self-signed certificate. Each client has its own pool.
func e2eClient(srv *e2eServer, tlsCfg *tls.Config) *http.Client {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	tlsCfg.InsecureSkipVerify = true //nolint:gosec // self-signed test server
	d := net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		// A client that only offers http/1.1 must not get h2 prepended.
		ForceAttemptHTTP2: !(len(tlsCfg.NextProtos) == 1 && tlsCfg.NextProtos[0] == "http/1.1"),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", srv.port))
		},
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// e2eGet performs a GET and returns the echoed fingerprints, the negotiated
// protocol and whether the connection was reused.
func e2eGet(t *testing.T, c *http.Client, srv *e2eServer) (fp e2eFingerprints, proto string, reused bool) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused },
	}))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(body), "|")
	if len(parts) != 4 {
		t.Fatalf("unexpected body %q", body)
	}
	return e2eFingerprints{
		JA3: parts[0], JA4: parts[1], JA3Raw: parts[2], Sorted: parts[3],
		HeaderJA3: resp.Header.Get("X-JA3"),
	}, resp.Proto, reused
}

var (
	ja3HashRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ja4RE     = regexp.MustCompile(`^[tq]1[23]d\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
)

func assertFingerprints(t *testing.T, fp e2eFingerprints, wantJA4Prefix string) {
	t.Helper()
	if !ja3HashRE.MatchString(fp.JA3) {
		t.Errorf("{tls.ja3} = %q, want a 32-char hex MD5", fp.JA3)
	}
	if !ja4RE.MatchString(fp.JA4) || !strings.HasPrefix(fp.JA4, wantJA4Prefix) {
		t.Errorf("{tls.ja4} = %q, want prefix %q and the JA4 shape", fp.JA4, wantJA4Prefix)
	}
	if !strings.HasPrefix(fp.JA3Raw, "771,") {
		t.Errorf("{tls.ja3_raw} = %q, want it to start with 771,", fp.JA3Raw)
	}
	if fp.HeaderJA3 != fp.JA3 {
		t.Errorf("X-JA3 header = %q, want %q", fp.HeaderJA3, fp.JA3)
	}
	if fp.Sorted != "false" {
		t.Errorf("{tls.ja3_sorted} = %q, want false", fp.Sorted)
	}
}

func TestE2E_TLSVersions(t *testing.T) {
	srv := startCaddy(t, "")
	for _, tc := range []struct {
		name       string
		version    uint16
		ja4Prefix  string
		wantProto  string
		nextProtos []string
	}{
		{"TLS 1.3 over HTTP/2", tls.VersionTLS13, "t13d", "HTTP/2.0", nil},
		{"TLS 1.2 over HTTP/2", tls.VersionTLS12, "t12d", "HTTP/2.0", nil},
		{"TLS 1.3 over HTTP/1.1", tls.VersionTLS13, "t13d", "HTTP/1.1", []string{"http/1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := e2eClient(srv, &tls.Config{
				MinVersion: tc.version, MaxVersion: tc.version, NextProtos: tc.nextProtos,
			})
			fp, proto, _ := e2eGet(t, c, srv)
			if proto != tc.wantProto {
				t.Errorf("negotiated %s, want %s", proto, tc.wantProto)
			}
			assertFingerprints(t, fp, tc.ja4Prefix)
		})
	}
}

// Several requests on one keep-alive connection must all see the fingerprint,
// and it must be the same one.
func TestE2E_KeepAliveKeepsFingerprint(t *testing.T) {
	srv := startCaddy(t, "")
	c := e2eClient(srv, &tls.Config{NextProtos: []string{"http/1.1"}})

	first, _, reused := e2eGet(t, c, srv)
	if reused {
		t.Fatal("first request cannot reuse a connection")
	}
	assertFingerprints(t, first, "t13d")
	for i := 0; i < 3; i++ {
		fp, _, reused := e2eGet(t, c, srv)
		if !reused {
			t.Fatalf("request %d did not reuse the connection", i+2)
		}
		if fp != first {
			t.Errorf("request %d: fingerprints changed on a live connection: %+v vs %+v", i+2, fp, first)
		}
	}
}

// Entries must not outlive their connection, otherwise a handshake flood
// grows the store until the TTL sweeper catches up.
func TestE2E_FingerprintRemovedWhenConnectionCloses(t *testing.T) {
	srv := startCaddy(t, "")
	store.sweep(0) // start from an empty store

	c := e2eClient(srv, &tls.Config{NextProtos: []string{"http/1.1"}})
	e2eGet(t, c, srv)
	if n := storeLen(); n != 1 {
		t.Fatalf("store has %d entries while the connection is open, want 1", n)
	}

	c.CloseIdleConnections()
	waitForEmptyStore(t)
}

// A handshake that completes but never sends a request (scanners, aborted
// clients) must not leave an entry behind either.
func TestE2E_FingerprintRemovedAfterBareHandshake(t *testing.T) {
	srv := startCaddy(t, "")
	store.sweep(0)

	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.port),
		&tls.Config{ServerName: "localhost", InsecureSkipVerify: true}) //nolint:gosec // self-signed test server
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Logf("close: %v", err)
	}

	waitForEmptyStore(t)
}

func storeLen() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.m)
}

// A resumed TLS session skips certificate selection, so the fingerprint has to
// be captured on every ClientHello, not only during GetCertificate.
func TestE2E_ResumedSessionIsFingerprinted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		version   uint16
		ja4Prefix string
	}{
		{"TLS 1.3", tls.VersionTLS13, "t13d"},
		{"TLS 1.2", tls.VersionTLS12, "t12d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startCaddy(t, "")

			var resumed []bool
			c := e2eClient(srv, &tls.Config{
				MinVersion:         tc.version,
				MaxVersion:         tc.version,
				NextProtos:         []string{"http/1.1"},
				ClientSessionCache: tls.NewLRUClientSessionCache(8),
				VerifyConnection: func(cs tls.ConnectionState) error {
					resumed = append(resumed, cs.DidResume)
					return nil
				},
			})

			first, _, _ := e2eGet(t, c, srv)
			assertFingerprints(t, first, tc.ja4Prefix)
			c.CloseIdleConnections()
			waitForEmptyStore(t)

			second, _, reused := e2eGet(t, c, srv)
			if reused {
				t.Fatal("the second request must use a new connection")
			}
			if len(resumed) != 2 || resumed[0] || !resumed[1] {
				t.Fatalf("test setup did not resume the session, DidResume per handshake = %v", resumed)
			}
			assertFingerprints(t, second, tc.ja4Prefix)
			if second.JA3 == "" || second.JA4 == "" {
				t.Errorf("resumed connection has no fingerprint: %+v", second)
			}
		})
	}
}

// waitForEmptyStore waits for ConnState cleanup to drain the global store.
func waitForEmptyStore(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for storeLen() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("store still has %d entries 5s after connections closed", storeLen())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// e2eGetH3 performs a GET over HTTP/3 against the test server's UDP listener.
func e2eGetH3(t *testing.T, tr *http3.Transport, srv *e2eServer) e2eFingerprints {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", srv.port), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = fmt.Sprintf("localhost:%d", srv.port)
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP/3 GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 3 {
		t.Fatalf("negotiated %s, want HTTP/3", resp.Proto)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(body), "|")
	if len(parts) != 4 {
		t.Fatalf("unexpected body %q", body)
	}
	return e2eFingerprints{JA3: parts[0], JA4: parts[1], JA3Raw: parts[2], Sorted: parts[3], HeaderJA3: resp.Header.Get("X-JA3")}
}

func TestE2E_HTTP3(t *testing.T) {
	if raceEnabled {
		// Caddy v2.11.4 itself trips the race detector here: TLS.Start writes
		// a field (keepStorageClean) that QUIC handshake goroutines, which are
		// not descended from Start, read through CaddyModule(). The detector
		// cannot see the ordering the loopback socket gives us. The HTTP/3 path
		// is still covered by the plain (non -race) test run.
		t.Skip("skipping under -race: upstream Caddy data race in TLS.Start")
	}
	srv := startCaddy(t, "", "servers {\n\t\tprotocols h1 h2 h3\n\t}")

	newTransport := func(cache tls.ClientSessionCache) *http3.Transport {
		return &http3.Transport{TLSClientConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // self-signed test server
			ClientSessionCache: cache,
		}}
	}

	t.Run("full handshake", func(t *testing.T) {
		tr := newTransport(nil)
		defer tr.Close()
		fp := e2eGetH3(t, tr, srv)
		assertFingerprints(t, fp, "q13d")
	})

	t.Run("resumed handshake", func(t *testing.T) {
		cache := tls.NewLRUClientSessionCache(8)

		tr1 := newTransport(cache)
		first := e2eGetH3(t, tr1, srv)
		assertFingerprints(t, first, "q13d")
		tr1.Close()

		tr2 := newTransport(cache)
		defer tr2.Close()
		second := e2eGetH3(t, tr2, srv)
		assertFingerprints(t, second, "q13d")
	})
}

func TestE2E_SortedFlagMatchesHash(t *testing.T) {
	srv := startCaddy(t, `
		ja3_ja4 {
			sort_ja3_extensions
		}
		respond "{tls.ja3}|{tls.ja4}|{tls.ja3_raw}|{tls.ja3_sorted}"`)

	c := e2eClient(srv, &tls.Config{NextProtos: []string{"http/1.1"}})
	fp, _, _ := e2eGet(t, c, srv)
	if fp.Sorted != "true" {
		t.Fatalf("{tls.ja3_sorted} = %q, want true", fp.Sorted)
	}

	// The raw string must really be sorted: extension IDs ascending.
	parts := strings.Split(fp.JA3Raw, ",")
	if len(parts) != 5 {
		t.Fatalf("unexpected JA3 raw %q", fp.JA3Raw)
	}
	prev := -1
	for _, id := range strings.Split(parts[2], "-") {
		n, err := strconv.Atoi(id)
		if err != nil || n < prev {
			t.Fatalf("extensions are not sorted ascending in %q", fp.JA3Raw)
		}
		prev = n
	}
}

// The store TTL must follow the server's idle timeout, otherwise connections
// kept alive longer than the old fixed 5 minutes lose their fingerprint.
func TestE2E_TTLFollowsConfiguredIdleTimeout(t *testing.T) {
	startCaddy(t, "", "servers {\n\t\ttimeouts {\n\t\t\tidle 20m\n\t\t}\n\t}")
	if got, want := store.TTL(), 20*time.Minute+ttlMargin; got < want {
		t.Errorf("store TTL = %v, want at least %v for idle_timeout 20m", got, want)
	}
}

// Several handler instances must share one sweeper, and unloading the config
// must release it.
func TestE2E_HandlersShareOneSweeper(t *testing.T) {
	store.sweepMu.Lock()
	startsBefore, refsBefore := store.sweepStarts, store.sweepRefs
	store.sweepMu.Unlock()

	startCaddy(t, `
		ja3_ja4
		ja3_ja4
		respond "{tls.ja3}|{tls.ja4}|{tls.ja3_raw}|{tls.ja3_sorted}"`)

	store.sweepMu.Lock()
	started, refs := store.sweepStarts-startsBefore, store.sweepRefs-refsBefore
	store.sweepMu.Unlock()
	if refs != 2 {
		t.Fatalf("two handlers hold %d sweeper references, want 2", refs)
	}
	if refsBefore == 0 && started != 1 {
		t.Errorf("two handlers started %d sweeper goroutines, want 1", started)
	}

	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := sweepRefs(); got != refsBefore {
		t.Errorf("sweeper references after unloading = %d, want %d", got, refsBefore)
	}
}
