package ja3ja4

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exaring/ja4plus"
)

const (
	// fingerprintTTL is how long a fingerprint entry may sit unused before the
	// sweeper reclaims it. It must comfortably exceed Caddy's default idle
	// timeout so entries for live keep-alive connections are never evicted
	// (Load/LoadByRemoteAddr refresh the timestamp on every hit).
	fingerprintTTL = 5 * time.Minute
	// sweepInterval is how often the background sweeper scans for expired entries.
	sweepInterval = 1 * time.Minute
	// defaultMaxEntries bounds the store so a flood of handshakes cannot grow
	// it without limit. Entries are normally removed as soon as their
	// connection closes, so this is only reached under abuse.
	defaultMaxEntries = 100_000
)

// fingerprintEntry pairs a fingerprint with a last-seen timestamp (unix nano)
// that is refreshed on every read, so the sweeper only reclaims entries for
// connections that have gone idle or closed without a cleanup hook.
type fingerprintEntry struct {
	fp       TLSFingerprint
	lastSeen atomic.Int64
}

// FingerprintStore is a thread-safe store for TLS fingerprints keyed by connection.
type FingerprintStore struct {
	mu  sync.RWMutex
	m   map[string]*fingerprintEntry
	max int
}

// NewFingerprintStore creates a new fingerprint store.
func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		m:   make(map[string]*fingerprintEntry),
		max: defaultMaxEntries,
	}
}

// Store saves a fingerprint for the given connection. It reports whether the
// fingerprint was kept: a new entry is dropped when the store is full, so that
// a handshake flood cannot evict fingerprints of live connections. Replacing
// the entry of an already-known connection always succeeds.
func (s *FingerprintStore) Store(conn net.Conn, fp TLSFingerprint) bool {
	key := connKey(conn)
	if key == "" {
		return false
	}
	e := &fingerprintEntry{fp: fp}
	e.lastSeen.Store(time.Now().UnixNano())

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[key]; !exists && len(s.m) >= s.max {
		return false
	}
	s.m[key] = e
	return true
}

// Load retrieves the fingerprint for the given connection.
func (s *FingerprintStore) Load(conn net.Conn) (TLSFingerprint, bool) {
	return s.LoadByRemoteAddr(connKey(conn))
}

// LoadByRemoteAddr retrieves the fingerprint by remote address string.
// This is used as a fallback for HTTP/3 requests where the net.Conn is not available in the request context.
func (s *FingerprintStore) LoadByRemoteAddr(remoteAddr string) (TLSFingerprint, bool) {
	if remoteAddr == "" {
		return TLSFingerprint{}, false
	}

	s.mu.RLock()
	e, ok := s.m[remoteAddr]
	s.mu.RUnlock()
	if !ok {
		return TLSFingerprint{}, false
	}

	e.lastSeen.Store(time.Now().UnixNano())
	return e.fp, true
}

// Delete removes the fingerprint for the given connection.
func (s *FingerprintStore) Delete(conn net.Conn) {
	key := connKey(conn)
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// sweep removes entries that have not been touched (via Store or a Load hit)
// within ttl. Long-lived, actively-used connections never expire since every
// lookup refreshes lastSeen; only idle or closed connections' entries age out.
func (s *FingerprintStore) sweep(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl).UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, e := range s.m {
		if e.lastSeen.Load() < cutoff {
			delete(s.m, key)
		}
	}
}

// StartSweeper launches a background goroutine that periodically reclaims
// stale fingerprint entries. It stops when ctx is done, so callers should tie
// ctx to the lifetime of the module that started it (e.g. a Caddy module's
// provisioning context).
func (s *FingerprintStore) StartSweeper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweep(fingerprintTTL)
			}
		}
	}()
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
// Go's crypto/tls does not expose the raw ClientHello.client_version field;
// see ja3Version for how it is reconstructed.
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

// extSupportedVersions is the TLS extension ID of supported_versions (RFC 8446).
const extSupportedVersions = 43

// legacyTLSVersion is the value RFC 8446 freezes ClientHello.legacy_version at
// whenever the supported_versions extension is sent.
const legacyTLSVersion = 0x0303

// ja3Version returns the JA3 SSLVersion field, i.e. ClientHello.client_version.
//
// Go does not expose that field directly. When the client sent the
// supported_versions extension, RFC 8446 pins client_version to 0x0303, so we
// can report it exactly. Otherwise Go derives SupportedVersions from the
// legacy version itself, so the first non-GREASE entry is that value.
// GREASE entries (RFC 8701) are never counted.
func ja3Version(chi *tls.ClientHelloInfo) string {
	if chi == nil {
		return "0"
	}
	if slices.Contains(chi.Extensions, extSupportedVersions) {
		return strconv.Itoa(legacyTLSVersion)
	}
	for _, v := range chi.SupportedVersions {
		if !isGREASE(v) {
			return strconv.FormatUint(uint64(v), 10)
		}
	}
	return "0"
}

func ja3Ciphers(chi *tls.ClientHelloInfo) string {
	if chi == nil || len(chi.CipherSuites) == 0 {
		return ""
	}
	ciphers := make([]string, 0, len(chi.CipherSuites))
	for _, cipher := range chi.CipherSuites {
		if !isGREASE(cipher) {
			ciphers = append(ciphers, strconv.FormatUint(uint64(cipher), 10))
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
		extStrs[i] = strconv.FormatUint(uint64(ext), 10)
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
		curveStrs[i] = strconv.FormatUint(uint64(curve), 10)
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
		formatStrs[i] = strconv.FormatUint(uint64(format), 10)
	}
	return strings.Join(formatStrs, "-")
}
