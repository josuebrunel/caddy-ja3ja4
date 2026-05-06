package ja3ja4

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// Register the directive with proper ordering.
func init() {
	httpcaddyfile.RegisterDirectiveOrder("ja3_ja4", "first")
}
