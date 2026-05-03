package tagger

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/twmb/murmur3"
)

// ShodanHash returns the 32-bit signed favicon hash that Shodan / Censys /
// FOFA index. The transformation is:
//
//  1. base64-encode the raw favicon bytes (standard padding).
//  2. insert a "\n" after every 76 characters and append a trailing "\n".
//  3. compute the 32-bit MurmurHash3 of the result, interpreted as a signed int.
//
// The newline-every-76-characters quirk comes from Python's
// base64.encodebytes which Shodan used in its original crawler. Matching
// that exactly is required for the hashes to compare against any of the
// public favicon-hash databases.
func ShodanHash(raw []byte) (int32, error) {
	if len(raw) == 0 {
		return 0, errors.New("empty favicon body")
	}

	encoded := base64.StdEncoding.EncodeToString(raw)

	var buf bytes.Buffer
	buf.Grow(len(encoded) + len(encoded)/76 + 1)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteByte('\n')
	}

	// Shodan uses the 32-bit MurmurHash3 with seed 0, then reads it as a
	// signed integer. Casting through int32 preserves the sign bit.
	return int32(murmur3.Sum32(buf.Bytes())), nil
}
