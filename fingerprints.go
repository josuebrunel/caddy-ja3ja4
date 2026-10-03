package ja3ja4

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exaring/ja4plus"
)

const (
	// defaultIdleTimeout mirrors the idle timeout Caddy applies to a server
	// that doesn't configure one.
	defaultIdleTimeout = 5 * time.Minute
	// ttlMargin is added on top of a server's idle timeout to get the
	// fingerprint TTL, so an entry never expires before Caddy would itself
	// close the idle connection.
	ttlMargin = 1 * time.Minute
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

// shardCount is the number of independently locked partitions of the store.
// Handshakes, lookups and the sweeper then contend per shard instead of on one
// global lock, and a sweep only ever blocks 1/shardCount of the keys at a time.
const shardCount = 32

// storeShard is one lock-protected partition of the store.
type storeShard struct {
	mu sync.RWMutex
	m  map[string]*fingerprintEntry
}

// FingerprintStore is a thread-safe store for TLS fingerprints keyed by connection.
type FingerprintStore struct {
	shards [shardCount]storeShard
	size   atomic.Int64 // entries across all shards, enforced against max
	max    int
	ttl    atomic.Int64 // time.Duration; see EnsureTTL

	sweepMu     sync.Mutex
	sweepRefs   int
	sweepCancel context.CancelFunc
	sweepStarts int // how many sweeper goroutines have been started (for tests)
}

// NewFingerprintStore creates a new fingerprint store.
func NewFingerprintStore() *FingerprintStore {
	s := &FingerprintStore{max: defaultMaxEntries}
	for i := range s.shards {
		s.shards[i].m = make(map[string]*fingerprintEntry)
	}
	s.ttl.Store(int64(ttlForIdleTimeout(0)))
	return s
}

// shard returns the partition responsible for key (FNV-1a, allocation-free).
func shard[K ~string | ~[]byte](s *FingerprintStore, key K) *storeShard {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h%shardCount]
}

// Len returns the number of stored fingerprints.
func (s *FingerprintStore) Len() int {
	return int(s.size.Load())
}

// ttlForIdleTimeout returns how long an unused fingerprint entry may live for a
// server with the given idle timeout (0 means Caddy's default). It must exceed
// the idle timeout, otherwise a live keep-alive connection could lose its
// fingerprint while Caddy still holds the connection open.
func ttlForIdleTimeout(idle time.Duration) time.Duration {
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	return idle + ttlMargin
}

// EnsureTTL raises the TTL to at least d. The store is shared by every server
// in the process, so it only ever grows to fit the longest idle timeout in
// use; a shorter value never shrinks it.
func (s *FingerprintStore) EnsureTTL(d time.Duration) {
	for {
		cur := s.ttl.Load()
		if int64(d) <= cur || s.ttl.CompareAndSwap(cur, int64(d)) {
			return
		}
	}
}

// TTL returns how long an unused entry is kept.
func (s *FingerprintStore) TTL() time.Duration {
	return time.Duration(s.ttl.Load())
}

// Touch marks the connection's entry as just used, without returning it. It is
// called when a connection goes idle so the idle period is measured from the
// end of its last request, not from its start.
func (s *FingerprintStore) Touch(conn net.Conn) {
	s.LoadByRemoteAddr(connKey(conn))
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

	sh := shard(s, key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, exists := sh.m[key]; !exists {
		// The cap is checked against the store-wide count, so it can be
		// overshot by a few entries when shards race; it is a safety bound,
		// not an exact quota.
		if s.size.Load() >= int64(s.max) {
			return false
		}
		s.size.Add(1)
	}
	sh.m[key] = e
	return true
}

// Load retrieves the fingerprint for the given connection.
func (s *FingerprintStore) Load(conn net.Conn) (TLSFingerprint, bool) {
	// Build the key on the stack: a lookup runs on every request and must not
	// allocate (net.Addr.String would, several times).
	var buf [64]byte
	key := appendConnKey(buf[:0], conn)
	if len(key) == 0 {
		return TLSFingerprint{}, false
	}
	sh := shard(s, key)
	sh.mu.RLock()
	e, ok := sh.m[string(key)] // the compiler elides this conversion for lookups
	sh.mu.RUnlock()
	if !ok {
		return TLSFingerprint{}, false
	}
	e.lastSeen.Store(time.Now().UnixNano())
	return e.fp, true
}

// LoadByRemoteAddr retrieves the fingerprint by remote address string.
// This is used as a fallback for HTTP/3 requests where the net.Conn is not available in the request context.
func (s *FingerprintStore) LoadByRemoteAddr(remoteAddr string) (TLSFingerprint, bool) {
	if remoteAddr == "" {
		return TLSFingerprint{}, false
	}

	sh := shard(s, remoteAddr)
	sh.mu.RLock()
	e, ok := sh.m[remoteAddr]
	sh.mu.RUnlock()
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
	sh := shard(s, key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.m[key]; ok {
		delete(sh.m, key)
		s.size.Add(-1)
	}
}

// sweep removes entries that have not been touched (via Store or a Load hit)
// within ttl. Long-lived, actively-used connections never expire since every
// lookup refreshes lastSeen; only idle or closed connections' entries age out.
// It locks one shard at a time.
func (s *FingerprintStore) sweep(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl).UnixNano()

	// One shard at a time, so handshakes and lookups on the other shards are
	// never held up by a sweep, however large the store has grown.
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for key, e := range sh.m {
			if e.lastSeen.Load() < cutoff {
				delete(sh.m, key)
				s.size.Add(-1)
			}
		}
		sh.mu.Unlock()
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
				s.sweep(s.TTL())
			}
		}
	}()
}

// AcquireSweeper starts the background sweeper if no one else has, and counts
// the caller as a user of it. Every call must be paired with ReleaseSweeper.
// The store is global and shared by every handler instance, so they share one
// goroutine instead of each sweeping the same map.
func (s *FingerprintStore) AcquireSweeper() {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	s.sweepRefs++
	if s.sweepRefs == 1 {
		ctx, cancel := context.WithCancel(context.Background())
		s.sweepCancel = cancel
		s.sweepStarts++
		s.StartSweeper(ctx)
	}
}

// ReleaseSweeper drops one user of the sweeper and stops it when none remain.
func (s *FingerprintStore) ReleaseSweeper() {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	if s.sweepRefs == 0 {
		return
	}
	s.sweepRefs--
	if s.sweepRefs == 0 {
		s.sweepCancel()
		s.sweepCancel = nil
	}
}

// connKey returns the store key of conn: its remote address as host:port.
func connKey(conn net.Conn) string {
	var buf [64]byte
	return string(appendConnKey(buf[:0], conn))
}

// appendConnKey appends conn's store key to dst. The key is the same text as
// conn.RemoteAddr().String(), which is also what http.Request.RemoteAddr holds,
// but TCP and UDP addresses are rendered without allocating. A nil connection
// or address yields an empty key.
func appendConnKey(dst []byte, conn net.Conn) []byte {
	if conn == nil {
		return dst
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return dst
	}
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	}
	if ap.Addr().IsValid() {
		// Unmap so an IPv4 client on a dual-stack socket reads "1.2.3.4:80", the
		// way net.IP.String prints it.
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).AppendTo(dst)
	}
	return append(dst, addr.String()...)
}

// Global store for fingerprints across all connections.
var store = NewFingerprintStore()

// TLSFingerprint holds computed JA3 and JA4 fingerprint values.
type TLSFingerprint struct {
	JA3    string
	JA3Raw string
	JA4    string
	// Sorted records whether the JA3 was computed with extensions, curves and
	// point formats sorted (sort_ja3_extensions), so the value reported to
	// requests matches how the hash was really produced.
	Sorted bool
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

// computeFingerprints computes JA3 (raw + hash) and JA4 from a ClientHello. It
// is the only place that handles a nil ClientHello (all three results are
// empty); the functions below require a non-nil one.
func computeFingerprints(chi *tls.ClientHelloInfo, sortExtensions bool) (string, string, string) {
	if chi == nil {
		return "", "", ""
	}

	ja3Raw, ja3 := computeJA3(chi, sortExtensions)
	ja4 := computeJA4(chi)

	return ja3Raw, ja3, ja4
}

// computeJA3 builds the JA3 fingerprint string and its MD5 hash.
//
// Go's crypto/tls does not expose the raw ClientHello.client_version field;
// see ja3Version for how it is reconstructed. It runs once per handshake, so
// the string is assembled in a single buffer rather than field by field.
func computeJA3(chi *tls.ClientHelloInfo, sortExtensions bool) (string, string) {
	var scratch [512]byte // a browser-sized JA3 string fits; append grows if not
	buf := appendJA3Version(scratch[:0], chi)
	buf = append(buf, ',')
	buf = appendJA3IDs(buf, chi.CipherSuites, false, true)
	buf = append(buf, ',')
	buf = appendJA3IDs(buf, chi.Extensions, sortExtensions, true)
	buf = append(buf, ',')
	buf = appendJA3IDs(buf, chi.SupportedCurves, sortExtensions, true)
	buf = append(buf, ',')
	buf = appendJA3IDs(buf, chi.SupportedPoints, sortExtensions, false)

	sum := md5.Sum(buf)
	var hexSum [md5.Size * 2]byte
	hex.Encode(hexSum[:], sum[:])
	return string(buf), string(hexSum[:])
}

// computeJA4 returns the JA4 fingerprint using the ja4plus library.
func computeJA4(chi *tls.ClientHelloInfo) string {
	return ja4plus.JA4(quicAware(chi))
}

// quicAware returns chi unchanged unless it came in over a UDP-based
// transport, in which case it returns a copy whose connection reports the
// "quic" network. ja4plus labels a "udp" connection as DTLS ('d'), but Go's
// crypto/tls cannot serve DTLS, so a handshake on a UDP socket here is always
// QUIC (HTTP/3), which JA4 labels 'q'.
func quicAware(chi *tls.ClientHelloInfo) *tls.ClientHelloInfo {
	if chi.Conn == nil {
		return chi
	}
	local := chi.Conn.LocalAddr()
	if local == nil || local.Network() != "udp" {
		return chi
	}
	c := *chi
	c.Conn = quicConn{chi.Conn}
	return &c
}

// quicConn reports its local address as belonging to the "quic" network.
type quicConn struct{ net.Conn }

func (c quicConn) LocalAddr() net.Addr { return quicAddr{c.Conn.LocalAddr()} }

type quicAddr struct{ net.Addr }

func (quicAddr) Network() string { return "quic" }

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
	return string(appendJA3Version(nil, chi))
}

func appendJA3Version(dst []byte, chi *tls.ClientHelloInfo) []byte {
	if slices.Contains(chi.Extensions, extSupportedVersions) {
		return strconv.AppendUint(dst, legacyTLSVersion, 10)
	}
	for _, v := range chi.SupportedVersions {
		if !isGREASE(v) {
			return strconv.AppendUint(dst, uint64(v), 10)
		}
	}
	return append(dst, '0')
}

func ja3Ciphers(chi *tls.ClientHelloInfo) string {
	return string(appendJA3IDs(nil, chi.CipherSuites, false, true))
}

func ja3Extensions(chi *tls.ClientHelloInfo, sortExts bool) string {
	return string(appendJA3IDs(nil, chi.Extensions, sortExts, true))
}

func ja3Curves(chi *tls.ClientHelloInfo, sortExts bool) string {
	return string(appendJA3IDs(nil, chi.SupportedCurves, sortExts, true))
}

func ja3PointFormats(chi *tls.ClientHelloInfo, sortExts bool) string {
	return string(appendJA3IDs(nil, chi.SupportedPoints, sortExts, false))
}

// appendJA3IDs appends ids to dst as decimal numbers joined by '-', optionally
// dropping GREASE values (RFC 8701) and sorting ascending. The input is never
// modified: GREASE filtering and sorting work on a copy, kept on the stack for
// the usual few dozen entries.
func appendJA3IDs[T ~uint8 | ~uint16](dst []byte, ids []T, sorted, dropGREASE bool) []byte {
	var stack [64]T
	kept := stack[:0]
	for _, id := range ids {
		if dropGREASE && isGREASE(uint16(id)) {
			continue
		}
		kept = append(kept, id)
	}
	if sorted {
		slices.Sort(kept)
	}
	for i, id := range kept {
		if i > 0 {
			dst = append(dst, '-')
		}
		dst = strconv.AppendUint(dst, uint64(id), 10)
	}
	return dst
}
