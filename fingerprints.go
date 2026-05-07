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

// LoadByRemoteAddr retrieves the fingerprint by remote address string.
// This is used as a fallback for HTTP/3 requests where the net.Conn is not available in the request context.
func (s *FingerprintStore) LoadByRemoteAddr(remoteAddr string) (TLSFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if remoteAddr == "" {
		return TLSFingerprint{}, false
	}
	fp, ok := s.m[remoteAddr]
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

// isGREASE reports whether v is a GREASE value as defined in RFC 8701.
// GREASE values follow the pattern where both bytes are equal and the low nibble
// of each byte is 0xA (e.g. 0x0A0A, 0x1A1A, 0x2A2A, …, 0xFAFA).
// The canonical JA3 specification excludes GREASE values from all fields.
func isGREASE(v uint16) bool {
	lo := byte(v)
	hi := byte(v >> 8)
	return lo == hi && lo&0x0f == 0x0a
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
//
// Known deviation: Go's crypto/tls does not expose the raw ClientHello.client_version
// field. This implementation uses SupportedVersions[0] as a best-effort approximation.
// For TLS 1.3 clients this yields 0x0304 rather than the legacy 0x0303 that reference
// implementations (e.g. Wireshark/tshark) produce, so hashes will differ for those clients.
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
	ciphers := make([]string, 0, len(chi.CipherSuites))
	for _, cipher := range chi.CipherSuites {
		if !isGREASE(cipher) {
			ciphers = append(ciphers, fmt.Sprintf("%d", cipher))
		}
	}
	return strings.Join(ciphers, "-")
}

func ja3Extensions(chi *tls.ClientHelloInfo, sortExts bool) string {
	if chi == nil || len(chi.Extensions) == 0 {
		return ""
	}
	exts := make([]uint16, 0, len(chi.Extensions))
	for _, ext := range chi.Extensions {
		if !isGREASE(ext) {
			exts = append(exts, ext)
		}
	}
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
	curves := make([]uint16, 0, len(chi.SupportedCurves))
	for _, c := range chi.SupportedCurves {
		if !isGREASE(uint16(c)) {
			curves = append(curves, uint16(c))
		}
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
