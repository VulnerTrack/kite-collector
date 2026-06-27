package customcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/filefingerprint"
)

const fullOverlay = `
api:
  - vendor: MyCorp
    product: Internal Gateway
    category: rest-api
    confidence: high
    probes:
      - path: /internal/health
        expected_status: [200]
        body_regex: '"service":"my-gateway"'
        header_name: X-MyCorp-Status

header:
  - vendor: MyCorp
    product: Internal WAF
    category: security
    patterns:
      - name: x-mycorp-waf
        header_name: X-MyCorp-WAF
        confidence: high

js:
  - vendor: MyCorp
    product: Internal SDK
    category: baas
    patterns:
      - name: mycorp-sdk
        regex: 'mycorp-sdk-v\d+'
        kind: script-src
        confidence: high

file:
  - path: /.mycorp-config
    description: Internal config file exposed
    category: secrets
    severity: high
    expected_status: [200]
    body_regex: 'MYCORP_TOKEN='

tls:
  - vendor: MyCorp
    product: Internal Cloud
    category: hosting
    patterns:
      - name: mycorp-cloud
        san_suffix: .mycorp.io
        kind: san-suffix
        confidence: high
`

func TestLoadBytes_FullOverlayCompiles(t *testing.T) {
	cats, err := LoadBytes([]byte(fullOverlay))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cats.API) != 1 {
		t.Errorf("API: got %d, want 1", len(cats.API))
	}
	if len(cats.Header) != 1 {
		t.Errorf("Header: got %d, want 1", len(cats.Header))
	}
	if len(cats.JS) != 1 {
		t.Errorf("JS: got %d, want 1", len(cats.JS))
	}
	if len(cats.File) != 1 {
		t.Errorf("File: got %d, want 1", len(cats.File))
	}
	if len(cats.TLS) != 1 {
		t.Errorf("TLS: got %d, want 1", len(cats.TLS))
	}
	// Spot-check API signature.
	sig := cats.API[0]
	if sig.Vendor != "MyCorp" || sig.Product != "Internal Gateway" {
		t.Errorf("API sig misparsed: %+v", sig)
	}
	if sig.Confidence != apifingerprint.ConfidenceHigh {
		t.Errorf("API confidence: got %q", sig.Confidence)
	}
	if len(sig.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(sig.Probes))
	}
	probe := sig.Probes[0]
	if probe.Path != "/internal/health" {
		t.Errorf("path: %q", probe.Path)
	}
	if !probe.HasMatcher() {
		t.Errorf("probe should have a matcher")
	}
	if probe.BodyRegex == nil {
		t.Errorf("body_regex should be compiled")
	}
	// File catalog spot-check.
	fp := cats.File[0]
	if fp.Severity != filefingerprint.SeverityHigh {
		t.Errorf("file severity: %q", fp.Severity)
	}
}

func TestLoadFile_MissingFileReturnsEmpty(t *testing.T) {
	cats, err := LoadFile("/nonexistent/path/that/does/not/exist.yaml")
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if len(cats.API) != 0 || len(cats.Header) != 0 {
		t.Errorf("expected empty catalogs on missing file")
	}
}

func TestLoadFile_ReadsActualFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fingerprints.yaml")
	if err := os.WriteFile(path, []byte(fullOverlay), 0o644); err != nil { //#nosec G306 -- fixture
		t.Fatalf("write: %v", err)
	}
	cats, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cats.API) != 1 {
		t.Errorf("expected 1 API sig, got %d", len(cats.API))
	}
}

func TestLoadBytes_InvalidRegexFailsLoad(t *testing.T) {
	bad := `
api:
  - vendor: X
    product: Y
    category: rest-api
    confidence: high
    probes:
      - path: /
        body_regex: '(unbalanced'
`
	_, err := LoadBytes([]byte(bad))
	if err == nil {
		t.Fatalf("expected error on invalid regex")
	}
	if !strings.Contains(err.Error(), "body_regex") {
		t.Errorf("expected error to mention body_regex, got %q", err.Error())
	}
}

func TestLoadBytes_MissingVendorFails(t *testing.T) {
	_, err := LoadBytes([]byte(`
api:
  - product: NoVendor
    category: x
    probes:
      - path: /x
        body_contains: y
`))
	if err == nil {
		t.Fatalf("expected error on missing vendor")
	}
}

func TestLoadBytes_FilePathMustStartWithSlash(t *testing.T) {
	_, err := LoadBytes([]byte(`
file:
  - path: notabs.txt
    description: x
    severity: high
    category: secrets
`))
	if err == nil {
		t.Fatalf("expected error on relative path")
	}
}

func TestLoadBytes_FileMissingDescription(t *testing.T) {
	_, err := LoadBytes([]byte(`
file:
  - path: /x
    severity: high
    category: secrets
`))
	if err == nil {
		t.Fatalf("expected error on missing description")
	}
}

func TestLoadBytes_HeaderRejectsBothHeaderAndCookie(t *testing.T) {
	_, err := LoadBytes([]byte(`
header:
  - vendor: X
    product: Y
    patterns:
      - name: bad
        header_name: X-Test
        cookie_name: PHPSESSID
        confidence: high
`))
	if err == nil {
		t.Fatalf("expected error when both header_name and cookie_name set")
	}
}

func TestLoadBytes_TLSRequiresExactlyOneMatcher(t *testing.T) {
	_, err := LoadBytes([]byte(`
tls:
  - vendor: X
    product: Y
    patterns:
      - name: bad
        san_suffix: .x.com
        issuer_regex: 'Let'
        confidence: high
`))
	if err == nil {
		t.Fatalf("expected error when SAN suffix and issuer regex both set")
	}
}

func TestLoadBytes_JSRequiresRegex(t *testing.T) {
	_, err := LoadBytes([]byte(`
js:
  - vendor: X
    product: Y
    patterns:
      - name: bad
        confidence: high
`))
	if err == nil {
		t.Fatalf("expected error on missing JS regex")
	}
}

func TestMerge_AppendsCustomAfterBase(t *testing.T) {
	cats, _ := LoadBytes([]byte(fullOverlay))
	base := apifingerprint.DefaultCatalog()
	merged := MergeAPI(base, cats.API)
	if len(merged) != len(base)+len(cats.API) {
		t.Errorf("merged len: got %d, want %d", len(merged), len(base)+len(cats.API))
	}
	if merged[len(base)].Vendor != "MyCorp" {
		t.Errorf("custom signatures should follow base")
	}
}

func TestLoadBytes_EmptyOverlayIsValid(t *testing.T) {
	cats, err := LoadBytes([]byte(""))
	if err != nil {
		t.Fatalf("empty overlay must not error: %v", err)
	}
	if len(cats.API) != 0 {
		t.Errorf("expected empty API catalog")
	}
}
