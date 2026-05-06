package ja3ja4

import (
	"context"
	"crypto/tls"

	ja4lib "github.com/exaring/ja4plus"
	ja3lib "github.com/dreadl0ck/ja3"
)

// Context key for storing fingerprints
type fpContextKey struct{}

// tlsFingerprint holds computed JA3/JA4 values
type tlsFingerprint struct {
	JA3 string
	JA4 string
}

// computeFingerprints calculates JA3 and JA4 from ClientHello info.
func computeFingerprints(chi *tls.ClientHelloInfo) (string, string) {
	var ja3, ja4 string

	// JA3 computation
	if chi.CipherSuites != nil && len(chi.CipherSuites) > 0 {
		j3, err := ja3lib.NewJA3FromClientHello(chi)
		if err != nil {
			ja3 = "error"
		} else {
			ja3 = j3
		}
	} else {
		ja3 = "n/a"
	}

	// JA4 computation
	j4, err := ja4lib.NewJA4FromClientHello(chi)
	if err != nil {
		ja4 = "error"
	} else {
		ja4 = j4
	}

	return ja3, ja4
}

// GetFingerprint retrieves fingerprint from context (for testing/internal use).
func GetFingerprint(ctx context.Context) (tlsFingerprint, bool) {
	fp, ok := ctx.Value(fpContextKey{}).(tlsFingerprint)
	return fp, ok
}
