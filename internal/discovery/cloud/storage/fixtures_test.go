package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// readFixture loads a JS fixture file by name. The fixtures live alongside
// the package in testdata/ so go test can find them via the standard
// convention.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func TestFixtures_DetectsKnownSDKs(t *testing.T) {
	cases := []struct {
		fixture  string
		provider Provider
	}{
		{"aws_sdk_v3.js", ProviderAWSS3},
		{"supabase_storage.js", ProviderSupabaseStorage},
		{"firebase_storage.js", ProviderGCS},
		{"azure_blob.js", ProviderAzureBlob},
		{"minio_js.js", ProviderMinIO},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			ev := Evidence{
				Filename: tc.fixture,
				JS:       readFixture(t, tc.fixture),
			}
			matches := Detect(ev)
			if !hasMatch(matches, tc.provider, SignalFile) {
				t.Fatalf("expected %s file match for %s, got %+v", tc.provider, tc.fixture, matches)
			}
		})
	}
}

func TestFixtures_NoCrossContamination(t *testing.T) {
	// Each fixture should fire its own provider's SignalFile rule and NOT
	// any other provider's. Catches over-broad regexes.
	cases := map[Provider]string{
		ProviderAWSS3:           "aws_sdk_v3.js",
		ProviderSupabaseStorage: "supabase_storage.js",
		ProviderGCS:             "firebase_storage.js",
		ProviderAzureBlob:       "azure_blob.js",
		ProviderMinIO:           "minio_js.js",
	}

	for owner, name := range cases {
		t.Run(name, func(t *testing.T) {
			ev := Evidence{Filename: name, JS: readFixture(t, name)}
			matches := Detect(ev)
			for _, m := range matches {
				if m.Signal != SignalFile {
					continue
				}
				if m.Provider != owner {
					t.Errorf("fixture %s (owner=%s) leaked file match for %s: %s",
						name, owner, m.Provider, m.Reason)
				}
			}
		})
	}
}
