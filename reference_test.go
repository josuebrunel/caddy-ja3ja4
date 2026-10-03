package ja3ja4

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// referenceJA3 is the straightforward, allocation-happy JA3 builder the
// production code used before it was optimised. It is kept as a test oracle:
// the fast implementation must produce byte-identical output.
func referenceJA3(chi *tls.ClientHelloInfo, sortExts bool) (string, string) {
	version := "0"
	if slices.Contains(chi.Extensions, 43) {
		version = "771"
	} else {
		for _, v := range chi.SupportedVersions {
			if !refGREASE(v) {
				version = strconv.Itoa(int(v))
				break
			}
		}
	}

	join := func(vals []uint16, filter bool) string {
		kept := make([]uint16, 0, len(vals))
		for _, v := range vals {
			if filter && refGREASE(v) {
				continue
			}
			kept = append(kept, v)
		}
		if sortExts {
			sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
		}
		strs := make([]string, len(kept))
		for i, v := range kept {
			strs[i] = strconv.Itoa(int(v))
		}
		return strings.Join(strs, "-")
	}

	ciphers := make([]string, 0, len(chi.CipherSuites))
	for _, c := range chi.CipherSuites { // ciphers are never sorted
		if !refGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}
	curves := make([]uint16, len(chi.SupportedCurves))
	for i, c := range chi.SupportedCurves {
		curves[i] = uint16(c)
	}
	points := make([]uint16, len(chi.SupportedPoints))
	for i, p := range chi.SupportedPoints {
		points[i] = uint16(p)
	}

	raw := fmt.Sprintf("%s,%s,%s,%s,%s", version, strings.Join(ciphers, "-"),
		join(chi.Extensions, true), join(curves, true), join(points, false))
	return raw, fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

// refGREASE is RFC 8701 written differently from the production isGREASE.
func refGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0x0f == 0x0a
}
