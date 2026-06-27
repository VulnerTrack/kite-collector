package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestParseSignaturesJSON_Array(t *testing.T) {
	body := `[
		{
			"provider": "my_provider",
			"signal": "file",
			"pattern": "(?i)my-storage-sdk",
			"description": "my-storage-sdk import",
			"confidence": 3
		}
	]`
	sigs, err := ParseSignaturesJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseSignaturesJSON: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("want 1 signature, got %d", len(sigs))
	}
	if sigs[0].Provider != "my_provider" || sigs[0].Signal != SignalFile {
		t.Errorf("decoded fields mismatch: %+v", sigs[0])
	}
	if sigs[0].Pattern == nil {
		t.Error("Pattern should be compiled")
	}
}

func TestParseSignaturesJSON_WrappedObject(t *testing.T) {
	body := `{"signatures": [
		{"provider":"p","signal":"bucket","pattern":"x","description":"d"}
	]}`
	sigs, err := ParseSignaturesJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseSignaturesJSON: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
}

func TestParseSignaturesYAML(t *testing.T) {
	body := `
signatures:
  - provider: yaml_provider
    signal: api
    pattern: "(?i)^x-yaml-"
    description: yaml header
    confidence: 2
`
	sigs, err := ParseSignaturesYAML([]byte(body))
	if err != nil {
		t.Fatalf("ParseSignaturesYAML: %v", err)
	}
	if len(sigs) != 1 || sigs[0].Provider != "yaml_provider" {
		t.Fatalf("yaml decode unexpected: %+v", sigs)
	}
}

func TestLoadSignaturesFromFile_DetectsExtension(t *testing.T) {
	jsonPath := writeTempFile(t, "sigs.json", `[{"provider":"j","signal":"tls","pattern":"x","description":"d"}]`)
	if _, err := LoadSignaturesFromFile(jsonPath); err != nil {
		t.Errorf("load .json: %v", err)
	}

	yamlPath := writeTempFile(t, "sigs.yaml", "- provider: y\n  signal: bucket\n  pattern: x\n  description: d\n")
	if _, err := LoadSignaturesFromFile(yamlPath); err != nil {
		t.Errorf("load .yaml: %v", err)
	}

	badExt := writeTempFile(t, "sigs.txt", "ignored")
	if _, err := LoadSignaturesFromFile(badExt); err == nil {
		t.Errorf("expected error for unsupported extension")
	}
}

func TestCompileSpec_Validations(t *testing.T) {
	cases := []struct {
		spec    SignatureSpec
		errSub  string
		wantOK  bool
		comment string
	}{
		{SignatureSpec{Provider: "p", Signal: "file", Description: "d", Pattern: "x"}, "", true, "happy path"},
		{SignatureSpec{Signal: "file", Description: "d", Pattern: "x"}, "provider is required", false, "missing provider"},
		{SignatureSpec{Provider: "p", Description: "d", Pattern: "x"}, "signal is required", false, "missing signal"},
		{SignatureSpec{Provider: "p", Signal: "bogus", Description: "d", Pattern: "x"}, "unknown signal", false, "invalid signal"},
		{SignatureSpec{Provider: "p", Signal: "file", Pattern: "x"}, "description is required", false, "missing description"},
		{SignatureSpec{Provider: "p", Signal: "file", Description: "d"}, "at least one of", false, "no payload"},
		{SignatureSpec{Provider: "p", Signal: "network", Description: "d", CIDRs: []string{"10.0.0.0/8"}}, "", true, "network with cidr"},
		{SignatureSpec{Provider: "p", Signal: "network", Description: "d", Pattern: "x"}, "signal=network requires cidrs", false, "network without cidr"},
		{SignatureSpec{Provider: "p", Signal: "network", Description: "d", CIDRs: []string{"not-a-cidr"}}, "invalid cidr", false, "bad cidr"},
		{SignatureSpec{Provider: "p", Signal: "file", Description: "d", Pattern: "(unclosed"}, "compile pattern", false, "bad regex"},
		{SignatureSpec{Provider: "p", Signal: "file", Description: "d", Pattern: "x", Confidence: 9}, "confidence", false, "confidence out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.comment, func(t *testing.T) {
			_, err := compileSpec(tc.spec)
			if tc.wantOK {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q", tc.errSub)
				} else if !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errSub)
				}
			}
		})
	}
}

func TestMergedCatalogue_KeepsBuiltinFirst(t *testing.T) {
	extra := []Signature{{Provider: "x", Signal: SignalFile, Description: "extra"}}
	merged := MergedCatalogue(extra)
	if len(merged) != len(catalogue)+1 {
		t.Fatalf("merged length unexpected: %d", len(merged))
	}
	// Built-in entries come first; the appended extra lives at the tail.
	if string(merged[len(merged)-1].Provider) != "x" {
		t.Errorf("expected extra signature at the tail, got %+v", merged[len(merged)-1])
	}
}

func TestCompileSpec_DefaultsToMediumConfidence(t *testing.T) {
	sig, err := compileSpec(SignatureSpec{
		Provider:    "p",
		Signal:      "file",
		Description: "d",
		Pattern:     "x",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Confidence != ConfidenceMedium {
		t.Errorf("expected default Confidence=medium, got %d", sig.Confidence)
	}
}

func TestParseSignaturesJSON_EmptyArrayErrors(t *testing.T) {
	if _, err := ParseSignaturesJSON([]byte(`[]`)); err == nil {
		t.Error("expected error for empty array")
	}
}
