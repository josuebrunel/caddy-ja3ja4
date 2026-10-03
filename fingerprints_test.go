package ja3ja4

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
	e := entryFor(s, key)
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
	e := entryFor(s, key)
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

// mockConn is a minimal net.Conn for testing; only RemoteAddr and LocalAddr
// (which JA4 reads to tell TCP from QUIC) are implemented.
type mockConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockConn) LocalAddr() net.Addr  { return &mockAddr{s: "127.0.0.1:443"} }

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

func TestJA3Version(t *testing.T) {
	tests := []struct {
		name string
		chi  *tls.ClientHelloInfo
		want string
	}{
		{
			name: "GREASE first with supported_versions extension (Chrome-like)",
			chi: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{0x5a5a, tls.VersionTLS13, tls.VersionTLS12},
				Extensions:        []uint16{0x0a0a, 0, 43, 16},
			},
			want: "771",
		},
		{
			name: "TLS 1.3 client without GREASE reports legacy version",
			chi: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
				Extensions:        []uint16{0, 43},
			},
			want: "771",
		},
		{
			name: "no extension, GREASE entry is skipped",
			chi: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{0xcaca, tls.VersionTLS12, tls.VersionTLS11},
			},
			want: "771",
		},
		{
			name: "TLS 1.2 only client",
			chi:  &tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS12}},
			want: "771",
		},
		{
			name: "legacy TLS 1.0 client",
			chi:  &tls.ClientHelloInfo{SupportedVersions: []uint16{tls.VersionTLS10}},
			want: "769",
		},
		{
			name: "only GREASE versions",
			chi:  &tls.ClientHelloInfo{SupportedVersions: []uint16{0x2a2a}},
			want: "0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ja3Version(tt.chi); got != tt.want {
				t.Errorf("ja3Version = %q, want %q", got, tt.want)
			}
		})
	}
}

// A GREASE value in the version list must not change the JA3 hash.
func TestComputeJA3_GREASEVersionIsStable(t *testing.T) {
	mk := func(grease uint16) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			SupportedVersions: []uint16{grease, tls.VersionTLS13, tls.VersionTLS12},
			CipherSuites:      []uint16{0x1301, 0x1302},
			Extensions:        []uint16{0, 43, 16},
			SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
			SupportedPoints:   []uint8{0},
		}
	}
	rawA, hashA := computeJA3(mk(0x0a0a), false)
	rawB, hashB := computeJA3(mk(0xfafa), false)
	if rawA != rawB || hashA != hashB {
		t.Errorf("JA3 differs across GREASE values: %q vs %q", rawA, rawB)
	}
	if !strings.HasPrefix(rawA, "771,") {
		t.Errorf("expected JA3 to start with 771, got %q", rawA)
	}
}

func TestFingerprintStore_CapDropsNewEntries(t *testing.T) {
	s := NewFingerprintStore()
	s.max = 2

	c1 := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.1:1"}}
	c2 := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.1:2"}}
	c3 := &mockConn{remoteAddr: &mockAddr{s: "10.0.0.1:3"}}

	if !s.Store(c1, TLSFingerprint{JA3: "one"}) || !s.Store(c2, TLSFingerprint{JA3: "two"}) {
		t.Fatal("entries below the cap must be stored")
	}
	if s.Store(c3, TLSFingerprint{JA3: "three"}) {
		t.Error("a new entry beyond the cap must be dropped")
	}
	if _, ok := s.Load(c3); ok {
		t.Error("dropped entry must not be loadable")
	}
	if fp, ok := s.Load(c1); !ok || fp.JA3 != "one" {
		t.Error("existing entries must survive a full store")
	}

	// Replacing an already-known connection is always allowed.
	if !s.Store(c1, TLSFingerprint{JA3: "one-v2"}) {
		t.Error("replacing an existing entry must succeed when full")
	}
	if fp, _ := s.Load(c1); fp.JA3 != "one-v2" {
		t.Errorf("expected replaced entry, got %q", fp.JA3)
	}

	// Freeing a slot makes room again.
	s.Delete(c2)
	if !s.Store(c3, TLSFingerprint{JA3: "three"}) {
		t.Error("store must accept entries again after one is deleted")
	}
}

func TestConnStateFunc_DeletesOnClose(t *testing.T) {
	for _, closing := range []http.ConnState{http.StateClosed, http.StateHijacked} {
		conn := &mockConn{remoteAddr: &mockAddr{s: "192.0.2.1:4000"}}
		store.Store(conn, TLSFingerprint{JA3: "x"})

		for _, live := range []http.ConnState{http.StateNew, http.StateActive, http.StateIdle} {
			connStateFunc(conn, live)
			if _, ok := store.Load(conn); !ok {
				t.Fatalf("fingerprint must survive state %v", live)
			}
		}

		connStateFunc(conn, closing)
		if _, ok := store.Load(conn); ok {
			t.Errorf("fingerprint must be removed on %v", closing)
		}
	}
}

type netConn struct {
	net.Conn
	local net.Addr
}

func (c *netConn) LocalAddr() net.Addr { return c.local }

type netAddr string

func (a netAddr) Network() string { return string(a) }
func (a netAddr) String() string  { return "127.0.0.1:443" }

func TestComputeJA4_TransportPrefix(t *testing.T) {
	for _, tc := range []struct {
		network string
		want    byte
	}{
		{"tcp", 't'},
		{"udp", 'q'}, // QUIC sockets: Go's TLS server never speaks DTLS
	} {
		chi := &tls.ClientHelloInfo{
			Conn:              &netConn{local: netAddr(tc.network)},
			SupportedVersions: []uint16{tls.VersionTLS13},
			CipherSuites:      []uint16{0x1301},
			Extensions:        []uint16{0, 43},
		}
		if got := computeJA4(chi); got[0] != tc.want {
			t.Errorf("network %q: JA4 %q starts with %q, want %q", tc.network, got, got[0], tc.want)
		}
		if chi.Conn.LocalAddr().Network() != tc.network {
			t.Errorf("computeJA4 must not modify the caller's ClientHelloInfo")
		}
	}
}

func TestHandshakeMatcher_RecordsAndAlwaysMatches(t *testing.T) {
	m := &HandshakeMatcher{}
	if !m.Match(nil) {
		t.Error("Match(nil) must still report true so it never changes policy selection")
	}
	if !m.Match(&tls.ClientHelloInfo{}) {
		t.Error("Match without a connection must report true")
	}

	conn := &mockConn{remoteAddr: &mockAddr{s: "198.51.100.7:5555"}}
	t.Cleanup(func() { store.Delete(conn) })
	chi := &tls.ClientHelloInfo{
		Conn:              conn,
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{0x1301},
		Extensions:        []uint16{0, 43},
	}
	if !m.Match(chi) {
		t.Fatal("Match must report true")
	}
	fp, ok := store.Load(conn)
	if !ok || len(fp.JA3) != 32 || fp.JA4 == "" {
		t.Errorf("matcher did not record the fingerprint: %+v ok=%v", fp, ok)
	}
}

// Without a fingerprint the placeholders must resolve to empty strings: Caddy
// leaves unknown placeholders as literal text in header values, which would
// send "{tls.ja3}" to the upstream.
func TestServeHTTP_NoFingerprint_PlaceholdersAreEmpty(t *testing.T) {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234" // nothing stored for this address

	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	m := &JA3JA4{SortJA3Extensions: true}
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"tls.ja3", "tls.ja4", "tls.ja3_raw", "tls.ja3_sorted"} {
		// ReplaceKnown(…, "") is exactly what header/header_up do.
		if got := repl.ReplaceKnown("[{"+key+"}]", ""); got != "[]" {
			t.Errorf("%s: header-style replacement = %q, want %q", key, got, "[]")
		}
	}
}

// {tls.ja3_sorted} must describe how the stored hash was computed, not the
// config of whichever handler happens to serve the request.
func TestServeHTTP_ReportsSortedFromFingerprint(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fpSorted    bool
		handlerSort bool
		want        string
	}{
		{"hash sorted, handler unsorted", true, false, "true"},
		{"hash unsorted, handler sorted", false, true, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &mockConn{remoteAddr: &mockAddr{s: "192.0.2.50:7000"}}
			store.Store(conn, TLSFingerprint{JA3: "abc", JA4: "def", JA3Raw: "raw", Sorted: tc.fpSorted})
			t.Cleanup(func() { store.Delete(conn) })

			repl := caddy.NewReplacer()
			ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
			ctx = context.WithValue(ctx, connCtxKey{}, net.Conn(conn))
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)

			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
			m := &JA3JA4{SortJA3Extensions: tc.handlerSort}
			if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
				t.Fatal(err)
			}
			if got := repl.ReplaceAll("{tls.ja3_sorted}", ""); got != tc.want {
				t.Errorf("{tls.ja3_sorted} = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandshakeMatcher_RecordsSortedFlag(t *testing.T) {
	for _, sorted := range []bool{false, true} {
		conn := &mockConn{remoteAddr: &mockAddr{s: fmt.Sprintf("192.0.2.60:%d", 8000+btoi(sorted))}}
		t.Cleanup(func() { store.Delete(conn) })
		(&HandshakeMatcher{SortJA3Extensions: sorted}).Match(&tls.ClientHelloInfo{
			Conn:              conn,
			SupportedVersions: []uint16{tls.VersionTLS13},
			Extensions:        []uint16{16, 0},
		})
		if fp, ok := store.Load(conn); !ok || fp.Sorted != sorted {
			t.Errorf("sorted=%v: stored fingerprint has Sorted=%v (found=%v)", sorted, fp.Sorted, ok)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestInstallMatcher(t *testing.T) {
	newPolicies := func() caddytls.ConnectionPolicies {
		return caddytls.ConnectionPolicies{{}, {}}
	}
	sortOf := func(t *testing.T, cp *caddytls.ConnectionPolicy) bool {
		t.Helper()
		var m HandshakeMatcher
		if err := json.Unmarshal(cp.MatchersRaw[matcherName], &m); err != nil {
			t.Fatal(err)
		}
		return m.SortJA3Extensions
	}

	t.Run("installs in every policy", func(t *testing.T) {
		cps := newPolicies()
		if err := installMatcher(cps, true, zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		for i, cp := range cps {
			if _, ok := cp.MatchersRaw[matcherName]; !ok || !sortOf(t, cp) {
				t.Errorf("policy %d: matcher missing or not sorted", i)
			}
		}
	})

	t.Run("keeps other matchers", func(t *testing.T) {
		cps := newPolicies()
		cps[0].MatchersRaw = caddy.ModuleMap{"sni": json.RawMessage(`["example.com"]`)}
		if err := installMatcher(cps, false, zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		if string(cps[0].MatchersRaw["sni"]) != `["example.com"]` {
			t.Error("existing matcher was modified")
		}
	})

	t.Run("first handler wins and a conflict is logged", func(t *testing.T) {
		cps := newPolicies()
		core, logs := observer.New(zap.WarnLevel)

		if err := installMatcher(cps, false, zap.New(core)); err != nil {
			t.Fatal(err)
		}
		if err := installMatcher(cps, true, zap.New(core)); err != nil {
			t.Fatal(err)
		}
		for i, cp := range cps {
			if sortOf(t, cp) {
				t.Errorf("policy %d: the later handler replaced the first one's setting", i)
			}
		}
		if logs.Len() != 1 {
			t.Errorf("expected exactly one warning for the conflict, got %d", logs.Len())
		}
	})

	t.Run("same setting is silent", func(t *testing.T) {
		cps := newPolicies()
		core, logs := observer.New(zap.WarnLevel)
		_ = installMatcher(cps, true, zap.New(core))
		_ = installMatcher(cps, true, zap.New(core))
		if logs.Len() != 0 {
			t.Errorf("unexpected warning: %v", logs.All())
		}
	})
}

func TestTTLForIdleTimeout(t *testing.T) {
	for _, tc := range []struct {
		idle time.Duration
		want time.Duration
	}{
		{0, defaultIdleTimeout + ttlMargin},            // Caddy applies its default
		{-time.Second, defaultIdleTimeout + ttlMargin}, // nonsense falls back to the default
		{30 * time.Second, 30*time.Second + ttlMargin}, // shorter than the default is honoured
		{10 * time.Minute, 10*time.Minute + ttlMargin}, // longer than the old fixed 5m TTL
		{2 * time.Hour, 2*time.Hour + ttlMargin},
	} {
		got := ttlForIdleTimeout(tc.idle)
		if got != tc.want {
			t.Errorf("idle %v: ttl = %v, want %v", tc.idle, got, tc.want)
		}
		if got <= tc.idle {
			t.Errorf("idle %v: ttl %v must exceed the idle timeout", tc.idle, got)
		}
	}
}

func TestFingerprintStore_EnsureTTLOnlyGrows(t *testing.T) {
	s := NewFingerprintStore()
	base := s.TTL()

	s.EnsureTTL(base / 2)
	if s.TTL() != base {
		t.Errorf("a shorter TTL must not shrink the store's: got %v, want %v", s.TTL(), base)
	}
	s.EnsureTTL(base * 3)
	if s.TTL() != base*3 {
		t.Errorf("TTL = %v, want %v", s.TTL(), base*3)
	}
}

// A request can outlive the TTL (large download, slow upstream); the entry must
// survive until the connection has been idle for a full TTL after it.
func TestConnStateFunc_IdleRestartsTheTTLClock(t *testing.T) {
	conn := &mockConn{remoteAddr: &mockAddr{s: "192.0.2.77:6000"}}
	store.Store(conn, TLSFingerprint{JA3: "x"})
	t.Cleanup(func() { store.Delete(conn) })

	age := func(d time.Duration) {
		entryFor(store, connKey(conn)).lastSeen.Store(time.Now().Add(-d).UnixNano())
	}

	age(2 * time.Hour) // the request has been running for two hours
	connStateFunc(conn, http.StateIdle)
	store.sweep(store.TTL())
	if _, ok := store.Load(conn); !ok {
		t.Fatal("entry was swept right after the connection went idle")
	}

	age(2 * time.Hour)
	store.sweep(store.TTL()) // no idle transition this time
	if _, ok := store.Load(conn); ok {
		t.Error("a genuinely stale entry must still be swept")
	}
}

// tls.context.ja3ja4 is no longer installed automatically but must keep
// recording for JSON configs that still reference it.
func TestHandshakeContextModule_StillRecords(t *testing.T) {
	conn := &mockConn{remoteAddr: &mockAddr{s: "192.0.2.88:9100"}}
	t.Cleanup(func() { store.Delete(conn) })

	m := &HandshakeContextModule{}
	if _, err := m.HandshakeContext(&tls.ClientHelloInfo{
		Conn:              conn,
		SupportedVersions: []uint16{tls.VersionTLS13},
		Extensions:        []uint16{0, 43},
	}); err != nil {
		t.Fatal(err)
	}
	if fp, ok := store.Load(conn); !ok || len(fp.JA3) != 32 {
		t.Errorf("fingerprint not recorded: %+v ok=%v", fp, ok)
	}
}

func TestFingerprintStore_SharedSweeperIsRefCounted(t *testing.T) {
	s := NewFingerprintStore()

	s.AcquireSweeper()
	s.AcquireSweeper()
	s.AcquireSweeper()
	if s.sweepStarts != 1 {
		t.Fatalf("3 users started %d sweepers, want 1", s.sweepStarts)
	}

	s.ReleaseSweeper()
	s.ReleaseSweeper()
	if s.sweepCancel == nil {
		t.Fatal("sweeper stopped while a user was still holding it")
	}
	s.ReleaseSweeper()
	if s.sweepCancel != nil || s.sweepRefs != 0 {
		t.Fatal("sweeper must stop once the last user releases it")
	}

	s.ReleaseSweeper() // an unbalanced release must be harmless
	if s.sweepRefs != 0 {
		t.Errorf("refs went negative: %d", s.sweepRefs)
	}

	s.AcquireSweeper()
	if s.sweepStarts != 2 {
		t.Errorf("a new user after a full stop must start a fresh sweeper, starts = %d", s.sweepStarts)
	}
	s.ReleaseSweeper()
}

func TestJA3JA4_CleanupReleasesOnlyWhatItAcquired(t *testing.T) {
	before := sweepRefs()

	unprovisioned := &JA3JA4{}
	if err := unprovisioned.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := sweepRefs(); got != before {
		t.Errorf("Cleanup of a never-provisioned handler changed the refcount: %d -> %d", before, got)
	}

	m := &JA3JA4{}
	store.AcquireSweeper()
	m.sweeping = true
	for i := 0; i < 2; i++ { // Cleanup twice must release once
		if err := m.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	if got := sweepRefs(); got != before {
		t.Errorf("refcount after Cleanup = %d, want %d", got, before)
	}
}

func sweepRefs() int {
	store.sweepMu.Lock()
	defer store.sweepMu.Unlock()
	return store.sweepRefs
}

// entryFor returns the raw entry stored under key, for tests that need to age it.
func entryFor(s *FingerprintStore, key string) *fingerprintEntry {
	sh := s.shard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.m[key]
}

// While one shard is locked (as it is during its slice of a sweep), the other
// shards must stay fully usable.
func TestFingerprintStore_SweepOnlyBlocksOneShard(t *testing.T) {
	s := NewFingerprintStore()

	// Find two keys that live in different shards.
	keyA := "10.0.0.1:1000"
	shardA := s.shard(keyA)
	var keyB string
	for port := 1001; ; port++ {
		keyB = fmt.Sprintf("10.0.0.1:%d", port)
		if s.shard(keyB) != shardA {
			break
		}
	}

	shardA.mu.Lock() // pretend the sweeper is working through shard A
	defer shardA.mu.Unlock()

	done := make(chan bool)
	go func() {
		conn := &mockConn{remoteAddr: &mockAddr{s: keyB}}
		ok := s.Store(conn, TLSFingerprint{JA3: "b"})
		_, loaded := s.Load(conn)
		done <- ok && loaded
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("Store/Load on an unlocked shard failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Store/Load on another shard blocked while one shard was locked")
	}
}

func TestFingerprintStore_LenTracksStoreDeleteAndSweep(t *testing.T) {
	s := NewFingerprintStore()
	conns := make([]*mockConn, 200) // spread over several shards
	for i := range conns {
		conns[i] = &mockConn{remoteAddr: &mockAddr{s: fmt.Sprintf("10.1.%d.%d:4000", i/250, i%250)}}
		s.Store(conns[i], TLSFingerprint{JA3: "x"})
	}
	if s.Len() != 200 {
		t.Fatalf("Len = %d, want 200", s.Len())
	}

	s.Store(conns[0], TLSFingerprint{JA3: "again"}) // replacing must not double count
	if s.Len() != 200 {
		t.Errorf("Len after replace = %d, want 200", s.Len())
	}

	for _, c := range conns[:50] {
		s.Delete(c)
		s.Delete(c) // deleting twice must not double decrement
	}
	if s.Len() != 150 {
		t.Errorf("Len after deletes = %d, want 150", s.Len())
	}

	s.sweep(0)
	if s.Len() != 0 {
		t.Errorf("Len after sweeping everything = %d, want 0", s.Len())
	}
}

// Known-answer vector from the JA3 specification's own README
// (github.com/salesforce/ja3). The hash was also re-derived with md5sum.
func TestComputeJA3_ReferenceVector(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS10}, // 769
		CipherSuites:      []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		Extensions:        []uint16{0, 10, 11},
		SupportedCurves:   []tls.CurveID{23, 24, 25},
		SupportedPoints:   []uint8{0},
	}
	raw, hash := computeJA3(chi, false)

	const wantRaw = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	const wantHash = "ada70206e40642a3e4461f35503241d5"
	if raw != wantRaw {
		t.Errorf("JA3 string = %q, want %q", raw, wantRaw)
	}
	if hash != wantHash {
		t.Errorf("JA3 hash = %q, want %q", hash, wantHash)
	}
}

// Chrome's published JA4 is t13d1516h2_8daaf6152771_02705d924276 (FoxIO). The
// middle segment is the SHA-256 (first 12 hex chars) of Chrome's 15 cipher
// suites sorted and comma-joined, which was re-derived independently. The
// last segment depends on the exact extension/signature-algorithm lists of the
// capture and cannot be reproduced here, so only the first two are asserted.
// GREASE values are mixed in everywhere to prove they are ignored.
func TestComputeJA4_ChromeReferenceSegments(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		ServerName:        "example.com", // SNI present -> 'd'
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x7a7a, tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites: []uint16{
			0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		// 16 real extensions (incl. SNI and ALPN) plus GREASE ones.
		Extensions: []uint16{
			0x2a2a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21, 0xfafa,
		},
		SignatureSchemes: []tls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}

	got := computeJA4(chi)
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 %q does not have 3 segments", got)
	}
	if parts[0] != "t13d1516h2" {
		t.Errorf("JA4 prefix = %q, want t13d1516h2", parts[0])
	}
	if parts[1] != "8daaf6152771" {
		t.Errorf("JA4 cipher hash = %q, want 8daaf6152771", parts[1])
	}
}
