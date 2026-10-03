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
	"strings"
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
	// unreadQUICTTL is how long a QUIC entry that no request has used yet may
	// live. QUIC has no close hook, and a handshake that never produces a request
	// (a scanner, an aborted client, a spoofed source) would otherwise hold its
	// slot for the whole TTL (the idle timeout plus a minute). A real HTTP/3
	// client sends its first request within moments of the handshake. Entries
	// that have served a request are not affected.
	unreadQUICTTL = 1 * time.Minute
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
	// read is set once a request has looked the entry up. Unread QUIC entries
	// expire after unreadQUICTTL instead of the full TTL.
	read atomic.Bool
	// sorted caches the sorted JA3 variant (see TLSFingerprint.WithSortedJA3),
	// built the first time a handler that sorts asks for it.
	sorted atomic.Pointer[sortedJA3]
}

// sortedJA3 is a JA3 string and hash computed with extensions, curves and point
// formats sorted.
type sortedJA3 struct {
	raw, hash string
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
	udp    atomic.Int64 // the QUIC share of size, enforced against max/2
	max    atomic.Int64 // capacity; see EnsureMax
	ttl    atomic.Int64 // time.Duration; see EnsureTTL

	sweepMu     sync.Mutex
	sweepRefs   int
	sweepCancel context.CancelFunc
	sweepStarts int // how many sweeper goroutines have been started (for tests)
}

// NewFingerprintStore creates a new fingerprint store.
func NewFingerprintStore() *FingerprintStore {
	s := &FingerprintStore{}
	s.max.Store(defaultMaxEntries)
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

// EnsureMax raises the capacity to at least n entries. Like EnsureTTL it only
// grows: the store is shared by every server in the process, so it fits the
// largest value any handler asks for.
func (s *FingerprintStore) EnsureMax(n int) {
	for {
		cur := s.max.Load()
		if int64(n) <= cur || s.max.CompareAndSwap(cur, int64(n)) {
			return
		}
	}
}

// Max returns the capacity of the store.
func (s *FingerprintStore) Max() int {
	return int(s.max.Load())
}

// TTL returns how long an unused entry is kept.
func (s *FingerprintStore) TTL() time.Duration {
	return time.Duration(s.ttl.Load())
}

// Touch marks the connection's entry as just used, without returning it. It is
// called when a connection goes idle so the idle period is measured from the
// end of its last request, not from its start.
func (s *FingerprintStore) Touch(conn net.Conn) {
	var buf [64]byte
	key := appendConnKey(buf[:0], conn)
	if len(key) == 0 {
		return
	}
	sh := shard(s, key)
	sh.mu.RLock()
	e, ok := sh.m[string(key)]
	sh.mu.RUnlock()
	if ok { // refresh the clock only: an idle connection has not used its fingerprint
		e.lastSeen.Store(time.Now().UnixNano())
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

	quic := isQUICKey(key)
	sh := shard(s, key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, exists := sh.m[key]; !exists {
		// The caps are checked against store-wide counts, so they can be
		// overshot by a few entries when shards race; they are safety bounds,
		// not exact quotas.
		if s.size.Load() >= s.max.Load() {
			return false
		}
		// QUIC entries get only half of the capacity. A TCP entry is removed
		// when its connection closes, but QUIC has no close hook, so QUIC
		// entries linger until they expire and a flood of QUIC handshakes (they
		// are processed before the client's address is verified) could
		// otherwise use every slot and leave TCP clients without a fingerprint.
		if quic {
			if s.udp.Load() >= s.quicBudget() {
				return false
			}
			s.udp.Add(1)
		}
		s.size.Add(1)
	}
	sh.m[key] = e
	return true
}

// quicBudget is how many entries QUIC connections may hold at once.
func (s *FingerprintStore) quicBudget() int64 {
	return s.max.Load() / 2
}

// isQUICKey reports whether a store key belongs to a QUIC connection.
func isQUICKey[K ~string | ~[]byte](key K) bool {
	return len(key) > 0 && key[0] == byte(TransportQUIC)
}

// Load retrieves the fingerprint for the given connection.
func (s *FingerprintStore) Load(conn net.Conn) (TLSFingerprint, bool) {
	// Build the key on the stack: a lookup runs on every request and must not
	// allocate (net.Addr.String would, several times).
	var buf [64]byte
	return s.load(appendConnKey(buf[:0], conn))
}

// LoadByRemoteAddr retrieves the fingerprint of a connection that arrived over
// transport t from remoteAddr (the text of http.Request.RemoteAddr). It is the
// fallback for requests where the net.Conn is not available, i.e. HTTP/3.
func (s *FingerprintStore) LoadByRemoteAddr(t Transport, remoteAddr string) (TLSFingerprint, bool) {
	if remoteAddr == "" {
		return TLSFingerprint{}, false
	}
	var buf [64]byte
	key := append(buf[:0], byte(t), ':')
	return s.load(append(key, remoteAddr...))
}

// load looks up a key built by appendConnKey and refreshes the entry's
// last-seen time.
func (s *FingerprintStore) load(key []byte) (TLSFingerprint, bool) {
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
	e.read.Store(true)
	fp := e.fp
	fp.entry = e // lets WithSortedJA3 cache its result on the entry
	return fp, true
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
		s.forget(key)
	}
}

// forget updates the counters for an entry that was just removed.
func (s *FingerprintStore) forget(key string) {
	s.size.Add(-1)
	if isQUICKey(key) {
		s.udp.Add(-1)
	}
}

// sweep removes entries that have not been touched (via Store or a Load hit)
// within ttl. Long-lived, actively-used connections never expire since every
// lookup refreshes lastSeen; only idle or closed connections' entries age out.
// Unread QUIC entries expire sooner (unreadQUICTTL). It locks one shard at a
// time.
func (s *FingerprintStore) sweep(ttl time.Duration) {
	now := time.Now()
	cutoff := now.Add(-ttl).UnixNano()
	unreadCutoff := now.Add(-min(ttl, unreadQUICTTL)).UnixNano()

	// One shard at a time, so handshakes and lookups on the other shards are
	// never held up by a sweep, however large the store has grown.
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for key, e := range sh.m {
			limit := cutoff
			if isQUICKey(key) && !e.read.Load() {
				limit = unreadCutoff
			}
			if e.lastSeen.Load() < limit {
				delete(sh.m, key)
				s.forget(key)
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

// Transport is the kind of socket a connection arrived on. It is part of the
// store key because a TCP connection and a QUIC (UDP) flow can come from the
// same ip:port, and must not overwrite each other's fingerprint.
type Transport byte

const (
	// TransportTCP is a TCP connection (HTTP/1.1, HTTP/2).
	TransportTCP Transport = 't'
	// TransportQUIC is a UDP flow carrying QUIC (HTTP/3).
	TransportQUIC Transport = 'u'
)

// transportOf reports which transport an address belongs to.
func transportOf(addr net.Addr) Transport {
	if addr == nil {
		return TransportTCP
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return TransportTCP
	case *net.UDPAddr:
		return TransportQUIC
	default:
		if n := a.Network(); n == "quic" || strings.HasPrefix(n, "udp") {
			return TransportQUIC
		}
		return TransportTCP
	}
}

// connKey returns the store key of conn: its transport and remote address, e.g.
// "t:203.0.113.7:50321".
func connKey(conn net.Conn) string {
	var buf [64]byte
	return string(appendConnKey(buf[:0], conn))
}

// appendConnKey appends conn's store key to dst. After the "t:" or "u:"
// transport prefix, the key is the same text as conn.RemoteAddr().String(),
// which is also what http.Request.RemoteAddr holds, but TCP and UDP addresses
// are rendered without allocating. A nil connection or address yields an empty
// key.
func appendConnKey(dst []byte, conn net.Conn) []byte {
	if conn == nil {
		return dst
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return dst
	}
	dst = append(dst, byte(transportOf(addr)), ':')

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

// TLSFingerprint holds computed JA3 and JA4 fingerprint values. JA3 and JA3Raw
// are always the unsorted (wire order) variant; WithSortedJA3 derives the other.
type TLSFingerprint struct {
	JA3    string
	JA3Raw string
	JA4    string

	entry *fingerprintEntry // the store entry it came from, if any (for caching)
}

// WithSortedJA3 returns the fingerprint with JA3 and JA3Raw replaced by the
// variant where extensions, curves and point formats are sorted by numeric ID
// (the sort_ja3_extensions option). JA4 is unchanged.
//
// The sorted variant is derived from the raw string rather than recomputed
// from the ClientHello: sorting only reorders fields 3 to 5 (ciphers are never
// sorted, and GREASE is already gone), so the handshake path never has to
// compute or store two variants, and each handler can choose its own.
func (f TLSFingerprint) WithSortedJA3() TLSFingerprint {
	var v *sortedJA3
	if f.entry != nil {
		v = f.entry.sorted.Load()
	}
	if v == nil {
		raw, hash := sortJA3(f.JA3Raw)
		v = &sortedJA3{raw: raw, hash: hash}
		if f.entry != nil {
			f.entry.sorted.CompareAndSwap(nil, v) // a lost race stored an identical value
		}
	}
	f.JA3Raw, f.JA3 = v.raw, v.hash
	return f
}

// sortJA3 derives the sorted JA3 string and its MD5 from an unsorted one. A
// string that isn't a well-formed JA3 (five comma-separated fields of numbers)
// is returned unchanged with its own hash.
func sortJA3(raw string) (sortedRaw, hash string) {
	fields := strings.Split(raw, ",")
	if len(fields) == 5 {
		var scratch [512]byte
		out := append(scratch[:0], fields[0]...)
		out = append(out, ',')
		out = append(out, fields[1]...) // ciphers keep their order
		ok := true
		for _, f := range fields[2:] {
			out = append(out, ',')
			if out, ok = appendSortedIDs(out, f); !ok {
				break
			}
		}
		if ok {
			raw = string(out)
		}
	}
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// appendSortedIDs appends the '-'-separated numbers in field to dst in
// ascending order. It reports false if the field has something else in it.
func appendSortedIDs(dst []byte, field string) ([]byte, bool) {
	if field == "" {
		return dst, true
	}
	var stack [64]uint16
	ids := stack[:0]
	for _, part := range strings.Split(field, "-") {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return dst, false
		}
		ids = append(ids, uint16(n))
	}
	return appendJA3IDs(dst, ids, true, false), true
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
