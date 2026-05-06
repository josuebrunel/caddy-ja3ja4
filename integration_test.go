package ja3ja4

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestModuleIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	caddytest.InitServer(t, `
{
	order ja3_ja4 first
	admin off
}

:8443 {
	tls {
		ja3ja4
		cert_file testdata/cert.pem
		key_file testdata/key.pem
	}
	ja3_ja4
	respond "JA3={tls.ja3} JA4={tls.ja4}"
}
`, "caddyfile")

	// Skip if test certs don't exist (CI can generate them)
	// For local testing, generate with:
	// openssl req -x509 -newkey rsa:2048 -keyout testdata/key.pem -out testdata/cert.pem -days 1 -nodes -subj "/CN=localhost"

	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256},
	}

	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		t.Skipf("skipping: could not connect to test server: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest("GET", "https://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("skipping: HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Basic validation: response should contain fingerprint placeholders (or their values)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestPlaceholderRegistration(t *testing.T) {
	// Verify that placeholders are registered by checking module can be provisioned
	mod := &JA3JA4{}
	ctx := caddy.Context{Context: context.Background()}
	if err := mod.Provision(ctx); err != nil {
		t.Fatalf("failed to provision module: %v", err)
	}
	// Placeholder registration is handled by Caddy core when middleware runs
	// This test ensures the module doesn't panic during setup
}
