package ja3ja4

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// resetStore empties the package-global fingerprint store now and again when
// the test ends. Tests that read or write the store (directly, through the
// handler, the matcher or a running Caddy) must call it so results never
// depend on test order or on leftovers from an earlier test.
func resetStore(t *testing.T) {
	t.Helper()
	empty := func() {
		for i := range store.shards {
			sh := &store.shards[i]
			sh.mu.Lock()
			for k := range sh.m {
				delete(sh.m, k)
			}
			sh.mu.Unlock()
		}
		store.size.Store(0)
	}
	empty()
	t.Cleanup(empty)
}

// TestMain fails the run when a test leaves entries in the global store, which
// would mean it forgot resetStore and may be coupled to other tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if n := store.Len(); code == 0 && n != 0 {
		fmt.Fprintf(os.Stderr, "FAIL: tests left %d entries in the global fingerprint store; call resetStore(t)\n", n)
		code = 1
	}
	os.Exit(code)
}

// deafConn sends packets normally but never delivers anything it receives, so
// the server's replies are lost. To the server that is exactly what a client
// with a spoofed source address looks like: its answers go to an address that
// never reads them.
type deafConn struct {
	net.PacketConn
	closed chan struct{}
	once   sync.Once
}

func newDeafConn(c net.PacketConn) *deafConn {
	return &deafConn{PacketConn: c, closed: make(chan struct{})}
}

func (d *deafConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-d.closed
	return 0, nil, net.ErrClosed
}

func (d *deafConn) Close() error {
	d.once.Do(func() { close(d.closed) })
	return d.PacketConn.Close()
}

// floodUnansweredQUIC sends n QUIC Initial packets to srv, each from a fresh
// source port and each ignoring the server's reply. The server processes the
// ClientHello of every one, but none ever completes a handshake or sends a
// request.
func floodUnansweredQUIC(t *testing.T, srv *e2eServer, n int) {
	t.Helper()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.port}

	jobs := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ { // well under Caddy's 1000 handshakes/s validation threshold
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					continue
				}
				dc := newDeafConn(pc)
				tr := &quic.Transport{Conn: dc}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				_, _ = tr.Dial(ctx, target, &tls.Config{
					ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h3"}, //nolint:gosec // self-signed test server
				}, &quic.Config{})
				cancel()
				_ = dc.Close() // unblock the transport's read loop before closing it
				_ = tr.Close()
			}
		}()
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond) // let the server finish processing
}
