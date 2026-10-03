package ja3ja4

import (
	"crypto/tls"
	"fmt"
	"testing"
)

// benchHello is shaped like a modern browser's ClientHello: GREASE values,
// 16 cipher suites, ~18 extensions, ALPN and signature algorithms.
func benchHello() *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x7a7a, tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites: []uint16{
			0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x2a2a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21, 0xfafa,
		},
		SupportedCurves:  []tls.CurveID{0x4a4a, tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:  []uint8{0},
		SignatureSchemes: []tls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}
}

func BenchmarkComputeJA3(b *testing.B) {
	chi := benchHello()
	b.ReportAllocs()
	for b.Loop() {
		computeJA3(chi, false)
	}
}

func BenchmarkComputeJA3_Sorted(b *testing.B) {
	chi := benchHello()
	b.ReportAllocs()
	for b.Loop() {
		computeJA3(chi, true)
	}
}

func BenchmarkComputeJA4(b *testing.B) {
	chi := benchHello()
	b.ReportAllocs()
	for b.Loop() {
		computeJA4(chi)
	}
}

// BenchmarkComputeFingerprints is the cost paid once per handshake.
func BenchmarkComputeFingerprints(b *testing.B) {
	chi := benchHello()
	b.ReportAllocs()
	for b.Loop() {
		computeFingerprints(chi, false)
	}
}

func benchConns(n int) []*mockConn {
	conns := make([]*mockConn, n)
	for i := range conns {
		conns[i] = &mockConn{remoteAddr: &mockAddr{s: fmt.Sprintf("10.%d.%d.%d:%d", i>>16&255, i>>8&255, i&255, 1024+i%60000)}}
	}
	return conns
}

// BenchmarkStoreLoad is the per-request lookup, from many goroutines.
func BenchmarkStoreLoad(b *testing.B) {
	s := NewFingerprintStore()
	conns := benchConns(10_000)
	for _, c := range conns {
		s.Store(c, TLSFingerprint{JA3: "x"})
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			s.Load(conns[i%len(conns)])
			i++
		}
	})
}

// BenchmarkStoreStoreDelete is a connection's lifecycle: one Store at the
// handshake and one Delete at close.
func BenchmarkStoreStoreDelete(b *testing.B) {
	s := NewFingerprintStore()
	conns := benchConns(10_000)
	fp := TLSFingerprint{JA3: "x"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c := conns[i%len(conns)]
			s.Store(c, fp)
			s.Delete(c)
			i++
		}
	})
}

// BenchmarkSweep scans a full-size store in which nothing has expired.
func BenchmarkSweep(b *testing.B) {
	s := NewFingerprintStore()
	for _, c := range benchConns(50_000) {
		s.Store(c, TLSFingerprint{JA3: "x"})
	}
	b.ResetTimer()
	for b.Loop() {
		s.sweep(s.TTL())
	}
}
