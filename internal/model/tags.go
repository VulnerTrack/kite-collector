package model

import (
	"encoding/json"
	"sort"
)

// MarshalTags serializes a tag map into a canonical JSON string. Keys are
// sorted ascending so the byte output is deterministic regardless of Go's
// map iteration order. The result is suitable for inclusion in any
// content-addressable digest (Asset.MaterialFingerprint relies on this).
//
// The encoded shape is `[[key, value], …]` — a sorted array of pairs
// rather than a JSON object — because the JSON spec does not require
// object key order to be preserved across encoders. A reader that later
// switches encoders (e.g. for a non-Go consumer) is still guaranteed
// byte-for-byte equality given the same input.
//
// An empty or nil map yields the empty string, not "[]", so the
// downstream MaterialFingerprint pre-image stays identical to today's
// "empty tags" representation.
func MarshalTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([][2]string, len(keys))
	for i, k := range keys {
		pairs[i] = [2]string{k, tags[k]}
	}
	out, _ := json.Marshal(pairs)
	return string(out)
}

// UnmarshalTags parses the canonical encoding produced by MarshalTags
// back into a map. An empty string returns nil to round-trip with
// MarshalTags's empty-map convention. Any other parse failure returns
// the error verbatim so callers can decide whether to tolerate it.
func UnmarshalTags(encoded string) (map[string]string, error) {
	if encoded == "" {
		return nil, nil
	}
	var pairs [][2]string
	if err := json.Unmarshal([]byte(encoded), &pairs); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		out[p[0]] = p[1]
	}
	return out, nil
}
