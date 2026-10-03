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
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
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
func startCaddy(t *testing.T, siteBody string) *e2eServer {
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
}
localhost:%d {
	bind 127.0.0.1
	tls %s %s
	%s
}
`, port, certPath, keyPath, siteBody)

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
	ja4RE     = regexp.MustCompile(`^t1[23]d\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
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
	deadline := time.Now().Add(5 * time.Second)
	for storeLen() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("store still has %d entries 5s after the connection closed", storeLen())
		}
		time.Sleep(10 * time.Millisecond)
	}
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

	deadline := time.Now().Add(5 * time.Second)
	for storeLen() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("store still has %d entries after a bare handshake closed", storeLen())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func storeLen() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.m)
}
