package dedup

import "encoding/base64"

// stdB64Decode is split out so canon.go can stay focused on the
// canonicalization rules rather than the encoding/base64 plumbing.
func stdB64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
