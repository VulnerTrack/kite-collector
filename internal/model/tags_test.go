package model

import (
	"math/rand"
	"testing"
)

func TestMarshalTags_DeterministicAcrossPermutations(t *testing.T) {
	base := map[string]string{
		"role":  "web",
		"env":   "prod",
		"team":  "platform",
		"owner": "infra",
	}
	want := MarshalTags(base)
	// Build many permutations of the same logical map.
	for trial := 0; trial < 1000; trial++ {
		perm := make(map[string]string, len(base))
		keys := []string{"role", "env", "team", "owner"}
		rand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		for _, k := range keys {
			perm[k] = base[k]
		}
		if got := MarshalTags(perm); got != want {
			t.Fatalf("non-deterministic encoding: %q vs %q", got, want)
		}
	}
}

func TestMarshalTags_EmptyIsEmptyString(t *testing.T) {
	if MarshalTags(nil) != "" {
		t.Error("nil map should encode as empty string")
	}
	if MarshalTags(map[string]string{}) != "" {
		t.Error("empty map should encode as empty string")
	}
}

func TestMarshalTags_RoundTrip(t *testing.T) {
	in := map[string]string{"k1": "v1", "k2": "v2 with spaces", "unicode": "ñoño"}
	encoded := MarshalTags(in)
	out, err := UnmarshalTags(encoded)
	if err != nil {
		t.Fatalf("UnmarshalTags: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("len = %d, want %d", len(out), len(in))
	}
	for k, v := range in {
		if out[k] != v {
			t.Errorf("%q = %q, want %q", k, out[k], v)
		}
	}
}

func TestMarshalTags_PreservesValueWhitespace(t *testing.T) {
	in := map[string]string{"k": "  v  "}
	out, err := UnmarshalTags(MarshalTags(in))
	if err != nil {
		t.Fatalf("UnmarshalTags: %v", err)
	}
	if out["k"] != "  v  " {
		t.Errorf("value whitespace lost: %q", out["k"])
	}
}
