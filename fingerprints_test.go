package ja3ja4

import (
	"crypto/tls"
	"reflect"
	"strings"
	"testing"
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

func TestCloneClientHelloWithSortedExtensions(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		Extensions: []uint16{0x0010, 0x0000, 0x0005},
	}

	cloned := cloneClientHelloWithSortedExtensions(chi)

	if !reflect.DeepEqual(chi.Extensions, []uint16{0x0010, 0x0000, 0x0005}) {
		t.Error("original was modified")
	}

	if !reflect.DeepEqual(cloned.Extensions, []uint16{0x0000, 0x0005, 0x0010}) {
		t.Errorf("expected sorted extensions, got %v", cloned.Extensions)
	}
}

func TestCloneClientHelloWithSortedExtensions_Nil(t *testing.T) {
	if got := cloneClientHelloWithSortedExtensions(nil); got != nil {
		t.Error("expected nil for nil input")
	}
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
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				t.Errorf("JA4 hash segment %d contains non-hex char %q in %q", i+1, string(c), hash)
				break
			}
		}
	}
}
