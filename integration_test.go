package ja3ja4

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestModuleProvision(t *testing.T) {
	mod := &JA3JA4{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := mod.Provision(ctx); err != nil {
		t.Fatalf("failed to provision module: %v", err)
	}
}

func TestCaddyfileParsing_SortOption(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		ja3_ja4 {
			sort_ja3_extensions
		}
	`)

	m := new(JA3JA4)
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("failed to parse Caddyfile: %v", err)
	}

	if !m.SortJA3Extensions {
		t.Error("expected SortJA3Extensions to be true")
	}
}

func TestCaddyfileParsing_InvalidSubdirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		ja3_ja4 {
			invalid_option
		}
	`)

	m := new(JA3JA4)
	err := m.UnmarshalCaddyfile(d)
	if err == nil {
		t.Error("expected error for invalid subdirective")
	}
}

func TestCaddyfileParsing_Default(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ja3_ja4`)

	m := new(JA3JA4)
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("failed to parse simple directive: %v", err)
	}

	if m.SortJA3Extensions {
		t.Error("expected SortJA3Extensions to be false by default")
	}
}

func TestHandshakeContextModule(t *testing.T) {
	mod := &HandshakeContextModule{}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := mod.Provision(ctx); err != nil {
		t.Fatalf("failed to provision handshake context: %v", err)
	}
}

func TestHandshakeContextModule_Caddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		ja3ja4 {
			sort_ja3_extensions
		}
	`)

	m := new(HandshakeContextModule)
	err := m.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("failed to parse Caddyfile: %v", err)
	}

	if !m.SortJA3Extensions {
		t.Error("expected SortJA3Extensions to be true")
	}
}
