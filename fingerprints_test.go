package ja3ja4

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestComputeJA3_NilInput(t *testing.T) {
	ja3Raw, ja3 := computeJA3(nil, false)
	if ja3Raw != "0,,," {
		t.Errorf("expected ja3Raw='0,,,', got %q", ja3Raw)
	}
	if ja3 != "" {
		t.Errorf("expected empty ja3 hash, got %q", ja3)
	}
}

func TestComputeFingerprints_NilInput(t *testing.T) {
	ja3Raw, ja3, ja4 := computeFingerprints(nil, false)
	if ja3Raw != "" || ja3 != "n/a" || ja4 != "n/a" {
		t.Errorf("expected empty/n/a for nil input, got %q %q %q", ja3Raw, ja3, ja4)
	}
}

func TestComputeJA3_Sorting(t *testing.T) {
	chi1 := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302},
		Extensions:        []uint16{0x0010, 0x0005, 0x0000},
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
	}

	chi2 := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302},
		Extensions:        []uint16{0x0000, 0x0005, 0x0010},
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
	}

	_, ja3a := computeJA3(chi1, false)
	_, ja3b := computeJA3(chi2, false)
	if ja3a == ja3b {
		t.Log("Note: JA3 identical without sorting (may happen if hash collision)")
	}

	_, ja3aSorted := computeJA3(chi1, true)
	_, ja3bSorted := computeJA3(chi2, true)
	if ja3aSorted != ja3bSorted {
		t.Errorf("JA3 with sorting should be identical: %q vs %q", ja3aSorted, ja3bSorted)
	}
}

func TestComputeJA3_ValidHash(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0xc02b, 0xc02f},
		Extensions:        []uint16{0x0000, 0x0005},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0, 1},
	}

	_, ja3 := computeJA3(chi, false)
	if len(ja3) != 32 {
		t.Errorf("expected 32-char MD5 hex hash, got %d chars: %q", len(ja3), ja3)
	}
}

func TestJA3Helpers(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0xc02b, 0xc02f},
		Extensions:        []uint16{0x0000, 0x0005},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0, 1},
	}

	if got := ja3Version(chi); got != "771" {
		t.Errorf("ja3Version: expected 771, got %q", got)
	}

	if got := ja3Ciphers(chi); got != "49195-49199" {
		t.Errorf("ja3Ciphers: expected '49195-49199', got %q", got)
	}

	if got := ja3Extensions(chi, false); got != "0-5" {
		t.Errorf("ja3Extensions: expected '0-5', got %q", got)
	}

	if got := ja3Curves(chi, false); got != "23" {
		t.Errorf("ja3Curves: expected '23', got %q", got)
	}

	if got := ja3PointFormats(chi, false); got != "0-1" {
		t.Errorf("ja3PointFormats: expected '0-1', got %q", got)
	}
}

func TestJA3Helpers_NilInput(t *testing.T) {
	if got := ja3Version(nil); got != "0" {
		t.Errorf("ja3Version(nil): expected '0', got %q", got)
	}
	if got := ja3Ciphers(nil); got != "" {
		t.Errorf("ja3Ciphers(nil): expected '', got %q", got)
	}
	if got := ja3Extensions(nil, false); got != "" {
		t.Errorf("ja3Extensions(nil): expected '', got %q", got)
	}
	if got := ja3Curves(nil, false); got != "" {
		t.Errorf("ja3Curves(nil): expected '', got %q", got)
	}
	if got := ja3PointFormats(nil, false); got != "" {
		t.Errorf("ja3PointFormats(nil): expected '', got %q", got)
	}
}

func TestJA3Extensions_SortingDoesNotMutateInput(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		Extensions: []uint16{0x0010, 0x0000, 0x0005},
	}
	original := []uint16{0x0010, 0x0000, 0x0005}

	// Sorting must not mutate the original slice.
	_ = ja3Extensions(chi, true)

	if !reflect.DeepEqual(chi.Extensions, original) {
		t.Errorf("ja3Extensions(sort=true) mutated original Extensions: %v", chi.Extensions)
	}
}

func TestJA3Extensions_SortedOutput(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		Extensions: []uint16{0x0010, 0x0000, 0x0005},
	}
	got := ja3Extensions(chi, true)
	if got != "0-5-16" {
		t.Errorf("expected sorted extensions '0-5-16', got %q", got)
	}
}

// uint16sFromBytes decodes a byte slice into big-endian uint16 values,
// discarding a trailing odd byte. Used to turn fuzzer-provided []byte input
// into the uint16 slices tls.ClientHelloInfo actually uses.
func uint16sFromBytes(b []byte) []uint16 {
	n := len(b) / 2
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = binary.BigEndian.Uint16(b[i*2 : i*2+2])
	}
	return out
}

// FuzzComputeJA3 exercises computeJA3/computeFingerprints with arbitrary
// ClientHello-shaped data, since these fields (cipher suites, extensions,
// curves, point formats) come directly from an attacker-controlled TLS
// handshake. It only asserts the function never panics and always returns a
// well-formed 5-field JA3 string; it makes no claim about specific values.
func FuzzComputeJA3(f *testing.F) {
	f.Add(uint16(tls.VersionTLS12), []byte{0xc0, 0x2b, 0xc0, 0x2f}, []byte{0x00, 0x00, 0x00, 0x05}, []byte{0x00, 0x17}, []byte{0, 1}, false)
	f.Add(uint16(tls.VersionTLS13), []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}, []byte{0xff, 0x01, 0x00, 0x2b}, []byte{0x00, 0x1d}, []byte{0}, true)
	f.Add(uint16(0), []byte{}, []byte{}, []byte{}, []byte{}, false)
	f.Add(uint16(0x0a0a), []byte{0x0a, 0x0a, 0x1a, 0x1a}, []byte{0x2a, 0x2a}, []byte{0xfa, 0xfa}, []byte{0}, true)

	f.Fuzz(func(t *testing.T, version uint16, ciphersRaw, extsRaw, curvesRaw, points []byte, sortExts bool) {
		curveIDs := uint16sFromBytes(curvesRaw)
		curves := make([]tls.CurveID, len(curveIDs))
		for i, c := range curveIDs {
			curves[i] = tls.CurveID(c)
		}

		chi := &tls.ClientHelloInfo{
			SupportedVersions: []uint16{version},
			CipherSuites:      uint16sFromBytes(ciphersRaw),
			Extensions:        uint16sFromBytes(extsRaw),
			SupportedCurves:   curves,
			SupportedPoints:   points,
		}

		raw, hash := computeJA3(chi, sortExts)
		if strings.Count(raw, ",") != 4 {
			t.Fatalf("malformed JA3 raw string, want 4 commas (5 fields): %q", raw)
		}
		if hash != "" && len(hash) != 32 {
			t.Fatalf("malformed JA3 MD5 hash, want 32 hex chars: %q", hash)
		}

		computeFingerprints(chi, sortExts)
	})
}

func TestComputeJA4_NilInput(t *testing.T) {
	ja4 := computeJA4(nil)
	if ja4 != "n/a" {
		t.Errorf("expected 'n/a', got %q", ja4)
	}
}

func TestFingerprintStore(t *testing.T) {
	s := NewFingerprintStore()

	_, ok := s.Load(nil)
	if ok {
		t.Error("expected false for nil connection")
	}

	fp := TLSFingerprint{JA3: "abc123", JA4: "def456", JA3Raw: "raw"}
	s.Store(nil, fp)

	_, ok = s.Load(nil)
	if ok {
		t.Error("expected false after storing nil connection")
	}

	s.Delete(nil) // should not panic
}

func TestFingerprintStore_SweepEvictsIdleEntries(t *testing.T) {
	s := NewFingerprintStore()
	conn := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.1:1111"}}
	s.Store(conn, TLSFingerprint{JA3: "abc"})

	s.sweep(0) // TTL of 0 makes any untouched entry immediately stale

	if _, ok := s.Load(conn); ok {
		t.Error("expected entry to be evicted by sweep")
	}
}

func TestFingerprintStore_LoadRefreshesLastSeen(t *testing.T) {
	s := NewFingerprintStore()
	conn := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.2:2222"}}
	s.Store(conn, TLSFingerprint{JA3: "abc"})

	// Simulate the entry aging past what a short TTL would allow, then
	// "use" it via Load before sweeping with that TTL. It must survive.
	key := connKey(conn)
	s.mu.RLock()
	e := s.m[key]
	s.mu.RUnlock()
	e.lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())

	if _, ok := s.Load(conn); !ok {
		t.Fatal("expected entry to still be present before sweep")
	}

	s.sweep(time.Minute)

	if _, ok := s.Load(conn); !ok {
		t.Error("expected active entry (refreshed via Load) to survive the sweep")
	}
}

func TestFingerprintStore_StartSweeperStopsOnContextDone(t *testing.T) {
	s := NewFingerprintStore()
	conn := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.3:3333"}}
	s.Store(conn, TLSFingerprint{JA3: "abc"})

	key := connKey(conn)
	s.mu.RLock()
	e := s.m[key]
	s.mu.RUnlock()
	e.lastSeen.Store(0) // already stale

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the sweeper's first tick fires

	s.StartSweeper(ctx)

	// Give the goroutine a moment to observe ctx.Done() and return; since ctx
	// is already cancelled it should exit before ever sweeping.
	time.Sleep(50 * time.Millisecond)

	if _, ok := s.Load(conn); !ok {
		t.Error("expected sweeper to have stopped before evicting the entry")
	}
}

func TestComputeJA4_TLS13(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x0000, 0x0005, 0x000a, 0x000b, 0x0010, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0xff01},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2", "http/1.1"},
	}

	ja4 := computeJA4(chi)

	if ja4 == "" {
		t.Fatal("JA4 should not be empty")
	}
	if ja4 == "n/a" {
		t.Fatal("JA4 should not be 'n/a' for valid ClientHelloInfo")
	}
	// JA4 format: t[version][cipher_count][ext_count][alpn]_[hash1]_[hash2]
	// Must start with 't' (TLS)
	if ja4[0] != 't' {
		t.Errorf("JA4 should start with 't', got %q", ja4[:1])
	}
	// Should contain two underscores (three segments)
	parts := 0
	for _, c := range ja4 {
		if c == '_' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("JA4 should have two underscores (3 parts), got %d in %q", parts, ja4)
	}
}

func TestComputeJA4_TLS12(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0xc02b, 0xc02f, 0x009c},
		Extensions:        []uint16{0x0000, 0x0005, 0x000a, 0x0017, 0x0023},
		SupportedCurves:   []tls.CurveID{tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0, 1},
		ServerName:        "test.example.com",
	}

	ja4 := computeJA4(chi)

	if ja4 == "" || ja4 == "n/a" {
		t.Fatalf("expected valid JA4, got %q", ja4)
	}
	if ja4[0] != 't' {
		t.Errorf("JA4 should start with 't', got %q", ja4[:1])
	}
}

func TestComputeJA4_DifferentInputs(t *testing.T) {
	chi1 := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302},
		Extensions:        []uint16{0x0000, 0x0005},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
	}

	chi2 := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0xc02b, 0xc02f},
		Extensions:        []uint16{0x0000, 0x0005},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
	}

	ja4a := computeJA4(chi1)
	ja4b := computeJA4(chi2)

	if ja4a == ja4b {
		t.Errorf("JA4 fingerprints should differ for different TLS versions: both got %q", ja4a)
	}
}

func TestComputeJA4_MinimalClientHello(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0x0000},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
	}

	ja4 := computeJA4(chi)

	if ja4 == "" || ja4 == "n/a" {
		t.Fatalf("expected valid JA4 for minimal ClientHello, got %q", ja4)
	}
}

func TestComputeJA4_Stability(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302},
		Extensions:        []uint16{0x0000, 0x0005, 0x0010},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
	}

	// Same input should always produce the same JA4
	ja4a := computeJA4(chi)
	ja4b := computeJA4(chi)
	ja4c := computeJA4(chi)

	if ja4a != ja4b || ja4b != ja4c {
		t.Errorf("JA4 should be stable across multiple calls: %q, %q, %q", ja4a, ja4b, ja4c)
	}
}

func TestComputeJA4_VerifiedFingerprintFormat(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x0000, 0x0005, 0x000a, 0x000b, 0x0010},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2", "http/1.1"},
	}

	ja4 := computeJA4(chi)

	// JA4 format: t[version][cipher_count][ext_count][alpn]_[hash1]_[hash2]
	// The first segment should contain: t + version(2 digits) + cipher_count(2 hex) + ext_count(2 hex) + alpn(1 char)
	// e.g. "t13d0315h2"
	segments := strings.Split(ja4, "_")
	if len(segments) != 3 {
		t.Fatalf("expected 3 underscore-separated segments, got %d in %q", len(segments), ja4)
	}

	// First segment should start with "t" and have version info
	prefix := segments[0]
	if len(prefix) < 6 {
		t.Errorf("JA4 prefix too short: %q", prefix)
	}
	if prefix[0] != 't' {
		t.Errorf("JA4 prefix should start with 't', got %q", prefix[:1])
	}

	// Hash segments should be hex
	for i, hash := range segments[1:] {
		if hash == "" {
			t.Errorf("JA4 hash segment %d is empty", i+1)
			continue
		}
		// Verify it's valid hex
		for _, c := range hash {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				t.Errorf("JA4 hash segment %d contains non-hex char %q in %q", i+1, string(c), hash)
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// GREASE filtering
// ---------------------------------------------------------------------------

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
		0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
		0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) should be true", v)
		}
	}
	nonGREASE := []uint16{0x0000, 0x0005, 0x000a, 0xc02b, 0x1301, tls.VersionTLS13}
	for _, v := range nonGREASE {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) should be false", v)
		}
	}
}

func TestJA3CiphersFiltersGREASE(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		CipherSuites: []uint16{0x0a0a, 0xc02b, 0x1a1a, 0xc02f},
	}
	got := ja3Ciphers(chi)
	if strings.Contains(got, "2570") { // 0x0a0a decimal
		t.Errorf("GREASE cipher 0x0a0a should be filtered, got %q", got)
	}
	if got != "49195-49199" {
		t.Errorf("expected '49195-49199' after GREASE filter, got %q", got)
	}
}

func TestJA3ExtensionsFiltersGREASE(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		Extensions: []uint16{0x0a0a, 0x0000, 0x2a2a, 0x0005},
	}
	got := ja3Extensions(chi, false)
	if strings.Contains(got, "2570") || strings.Contains(got, "10794") {
		t.Errorf("GREASE extensions should be filtered, got %q", got)
	}
	if got != "0-5" {
		t.Errorf("expected '0-5' after GREASE filter, got %q", got)
	}
}

func TestJA3CurvesFiltersGREASE(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedCurves: []tls.CurveID{tls.CurveID(0x0a0a), tls.CurveP256, tls.CurveID(0x1a1a)},
	}
	got := ja3Curves(chi, false)
	if strings.Contains(got, "2570") || strings.Contains(got, "6682") {
		t.Errorf("GREASE curves should be filtered, got %q", got)
	}
	if got != "23" {
		t.Errorf("expected '23' after GREASE filter, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP placeholder injection
// ---------------------------------------------------------------------------

// mockConn is a minimal net.Conn for testing; only RemoteAddr is used.
type mockConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }

type mockAddr struct{ s string }

func (a *mockAddr) Network() string { return "tcp" }
func (a *mockAddr) String() string  { return a.s }

func TestServeHTTP_PlaceholderInjection(t *testing.T) {
	conn := &mockConn{remoteAddr: &mockAddr{s: "1.2.3.4:9999"}}

	fp := TLSFingerprint{JA3: "abc123", JA3Raw: "771,49195,,23,0", JA4: "t13d0100h2_abc_def"}
	store.Store(conn, fp)
	defer store.Delete(conn)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, connCtxKey{}, net.Conn(conn))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	m := &JA3JA4{SortJA3Extensions: false}
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if !nextCalled {
		t.Error("next handler was not called")
	}

	cases := []struct{ key, want string }{
		{"tls.ja3", fp.JA3},
		{"tls.ja3_raw", fp.JA3Raw},
		{"tls.ja4", fp.JA4},
		{"tls.ja3_sorted", "false"},
	}
	for _, tc := range cases {
		got := repl.ReplaceAll("{"+tc.key+"}", "")
		if got != tc.want {
			t.Errorf("%s: expected %q, got %q", tc.key, tc.want, got)
		}
	}
}

func TestServeHTTP_NoConn_CallsNext(t *testing.T) {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	m := &JA3JA4{}
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Error("next handler was not called when conn missing")
	}
}
