package ja3ja4

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/exaring/ja4plus"
)

// FingerprintStore is a thread-safe store for TLS fingerprints keyed by connection.
type FingerprintStore struct {
	mu sync.RWMutex
	m  map[string]TLSFingerprint
}

// NewFingerprintStore creates a new fingerprint store.
func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		m: make(map[string]TLSFingerprint),
	}
}

// Store saves a fingerprint for the given connection.
func (s *FingerprintStore) Store(conn net.Conn, fp TLSFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := connKey(conn)
	if key != "" {
		s.m[key] = fp
	}
}

// Load retrieves the fingerprint for the given connection.
func (s *FingerprintStore) Load(conn net.Conn) (TLSFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := connKey(conn)
	if key == "" {
		return TLSFingerprint{}, false
	}
	fp, ok := s.m[key]
	return fp, ok
}

// Delete removes the fingerprint for the given connection.
func (s *FingerprintStore) Delete(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := connKey(conn)
	if key != "" {
		delete(s.m, key)
	}
}

func connKey(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

// Global store for fingerprints across all connections.
var store = NewFingerprintStore()

// TLSFingerprint holds computed JA3 and JA4 fingerprint values.
type TLSFingerprint struct {
	JA3    string
	JA3Raw string
	JA4    string
}

// computeFingerprints computes JA3 (raw + hash) and JA4 from a ClientHello.
func computeFingerprints(chi *tls.ClientHelloInfo, sortExtensions bool) (string, string, string) {
	if chi == nil {
		return "", "n/a", "n/a"
	}

	ja3Raw, ja3 := computeJA3(chi, sortExtensions)
	ja4 := computeJA4(chi)

	return ja3Raw, ja3, ja4
}

// computeJA3 builds the JA3 fingerprint string and its MD5 hash.
func computeJA3(chi *tls.ClientHelloInfo, sortExtensions bool) (string, string) {
	if chi == nil {
		return "0,,,", ""
	}

	version := ja3Version(chi)
	ciphers := ja3Ciphers(chi)
	extensions := ja3Extensions(chi, sortExtensions)
	curves := ja3Curves(chi, sortExtensions)
	pointFormats := ja3PointFormats(chi, sortExtensions)

	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s", version, ciphers, extensions, curves, pointFormats)
	hash := md5.Sum([]byte(ja3String))

	return ja3String, fmt.Sprintf("%x", hash)
}

// computeJA4 returns the JA4 fingerprint using the ja4plus library.
func computeJA4(chi *tls.ClientHelloInfo) string {
	if chi == nil {
		return "n/a"
	}
	return ja4plus.JA4(chi)
}

// cloneClientHelloWithSortedExtensions returns a deep copy of chi with
// extensions sorted by ID. The original chi is not modified.
func cloneClientHelloWithSortedExtensions(chi *tls.ClientHelloInfo) *tls.ClientHelloInfo {
	if chi == nil {
		return nil
	}

	cloned := &tls.ClientHelloInfo{
		CipherSuites:      make([]uint16, len(chi.CipherSuites)),
		ServerName:        chi.ServerName,
		SupportedCurves:   make([]tls.CurveID, len(chi.SupportedCurves)),
		SupportedPoints:   make([]uint8, len(chi.SupportedPoints)),
		SignatureSchemes:  make([]tls.SignatureScheme, len(chi.SignatureSchemes)),
		SupportedProtos:   make([]string, len(chi.SupportedProtos)),
		SupportedVersions: make([]uint16, len(chi.SupportedVersions)),
		Extensions:        make([]uint16, len(chi.Extensions)),
		Conn:              chi.Conn,
	}

	copy(cloned.CipherSuites, chi.CipherSuites)
	copy(cloned.SupportedCurves, chi.SupportedCurves)
	copy(cloned.SupportedPoints, chi.SupportedPoints)
	copy(cloned.SignatureSchemes, chi.SignatureSchemes)
	copy(cloned.SupportedProtos, chi.SupportedProtos)
	copy(cloned.SupportedVersions, chi.SupportedVersions)
	copy(cloned.Extensions, chi.Extensions)

	sort.Slice(cloned.Extensions, func(i, j int) bool {
		return cloned.Extensions[i] < cloned.Extensions[j]
	})

	return cloned
}

func ja3Version(chi *tls.ClientHelloInfo) string {
	if chi == nil || len(chi.SupportedVersions) == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", chi.SupportedVersions[0])
}

func ja3Ciphers(chi *tls.ClientHelloInfo) string {
	if chi == nil || len(chi.CipherSuites) == 0 {
		return ""
	}
	ciphers := make([]string, len(chi.CipherSuites))
	for i, cipher := range chi.CipherSuites {
		ciphers[i] = fmt.Sprintf("%d", cipher)
	}
	return strings.Join(ciphers, "-")
}

func ja3Extensions(chi *tls.ClientHelloInfo, sortExts bool) string {
	if chi == nil || len(chi.Extensions) == 0 {
		return ""
	}
	exts := make([]uint16, len(chi.Extensions))
	copy(exts, chi.Extensions)
	if sortExts {
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	}
	extStrs := make([]string, len(exts))
	for i, ext := range exts {
		extStrs[i] = fmt.Sprintf("%d", ext)
	}
	return strings.Join(extStrs, "-")
}

func ja3Curves(chi *tls.ClientHelloInfo, sortExts bool) string {
	if chi == nil || len(chi.SupportedCurves) == 0 {
		return ""
	}
	curves := make([]uint16, len(chi.SupportedCurves))
	for i, c := range chi.SupportedCurves {
		curves[i] = uint16(c)
	}
	if sortExts {
		sort.Slice(curves, func(i, j int) bool { return curves[i] < curves[j] })
	}
	curveStrs := make([]string, len(curves))
	for i, curve := range curves {
		curveStrs[i] = fmt.Sprintf("%d", curve)
	}
	return strings.Join(curveStrs, "-")
}

func ja3PointFormats(chi *tls.ClientHelloInfo, sortExts bool) string {
	if chi == nil || len(chi.SupportedPoints) == 0 {
		return ""
	}
	formats := make([]uint8, len(chi.SupportedPoints))
	copy(formats, chi.SupportedPoints)
	if sortExts {
		sort.Slice(formats, func(i, j int) bool { return formats[i] < formats[j] })
	}
	formatStrs := make([]string, len(formats))
	for i, format := range formats {
		formatStrs[i] = fmt.Sprintf("%d", format)
	}
	return strings.Join(formatStrs, "-")
}

// GetFingerprintFromContext is deprecated. Use the store directly.
func GetFingerprintFromContext(ctx interface{}) (TLSFingerprint, bool) {
	return TLSFingerprint{}, false
}
