package ja3ja4

import (
	"context"
	"crypto/tls"
	"testing"
)

func TestComputeFingerprints_NilClientHello(t *testing.T) {
	ja3, ja4 := computeFingerprints(nil)
	if ja3 != "n/a" {
		t.Errorf("expected ja3='n/a', got %q", ja3)
	}
	if ja4 != "error" {
		t.Errorf("expected ja4='error', got %q", ja4)
	}
}

func TestComputeFingerprints_EmptyClientHello(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		CipherSuites: []uint16{},
	}
	ja3, ja4 := computeFingerprints(chi)
	// Empty cipher suites should still produce valid output from libraries
	if ja3 == "" {
		t.Error("ja3 should not be empty")
	}
	if ja4 == "" {
		t.Error("ja4 should not be empty")
	}
}

func TestContextPropagation(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		CipherSuites: []uint16{0x1301, 0x1302},
		ServerName:   "example.com",
	}
	ja3, ja4 := computeFingerprints(chi)
	ctx := context.WithValue(context.Background(), fpContextKey{}, tlsFingerprint{JA3: ja3, JA4: ja4})

	fp, ok := GetFingerprint(ctx)
	if !ok {
		t.Fatal("failed to retrieve fingerprint from context")
	}
	if fp.JA3 != ja3 {
		t.Errorf("JA3 mismatch: expected %q, got %q", ja3, fp.JA3)
	}
	if fp.JA4 != ja4 {
		t.Errorf("JA4 mismatch: expected %q, got %q", ja4, fp.JA4)
	}
}
