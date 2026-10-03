package ja3ja4

import (
	"fmt"
	"os"
	"testing"
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
