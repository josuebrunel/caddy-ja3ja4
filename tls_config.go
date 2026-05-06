package ja3ja4

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// getTLSConfig returns a TLS config getter that injects fingerprinting.
func getTLSConfig(d *caddyfile.Dispenser, _ caddy.Context) (*tls.Config, error) {
	cfg := &tls.Config{}

	// Wrap GetConfigForClient to inject fingerprint logic
	original := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		nextCfg, err := original(chi)
		if err != nil {
			return nil, err
		}
		if nextCfg == nil {
			nextCfg = &tls.Config{}
		}
		nextCfg = nextCfg.Clone()

		// Inject fingerprint computation into GetClientHelloInfo
		origGetCHI := nextCfg.GetClientHelloInfo
		nextCfg.GetClientHelloInfo = func(chi *tls.ClientHelloInfo) (*tls.ClientHelloInfo, error) {
			ja3, ja4 := computeFingerprints(chi)
			ctx := context.WithValue(chi.Context(), fpContextKey{}, tlsFingerprint{JA3: ja3, JA4: ja4})
			chi = chi.Clone()
			chi.Context = ctx
			if origGetCHI != nil {
				return origGetCHI(chi)
			}
			return chi, nil
		}
		return nextCfg, nil
	}

	return cfg, nil
}
