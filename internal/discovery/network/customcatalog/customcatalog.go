// Package customcatalog loads operator-supplied YAML signature
// overlays for the five fingerprint packages (api, header, js, file,
// tls). Operators write rules in a single YAML file; the loader
// validates them, compiles the regexes, and returns slices ready to
// append to each package's DefaultCatalog at runtime.
//
// Schema overview (see testdata/example.yaml for a full sample):
//
//	api:
//	  - vendor: MyCorp
//	    product: Internal Gateway
//	    category: rest-api
//	    confidence: high
//	    probes:
//	      - path: /internal/health
//	        expected_status: [200]
//	        body_regex: '"service":"my-gateway"'
//	        header_name: X-MyCorp-Status
//
//	header:
//	  - vendor: MyCorp
//	    product: Internal WAF
//	    category: security
//	    patterns:
//	      - name: x-mycorp-waf
//	        header_name: X-MyCorp-WAF
//	        confidence: high
//
//	js:
//	  - vendor: MyCorp
//	    product: Internal SDK
//	    category: baas
//	    patterns:
//	      - name: mycorp-sdk
//	        regex: 'mycorp-sdk-v\d+'
//	        kind: script-src
//	        confidence: high
//
//	file:
//	  - path: /.mycorp-config
//	    description: Internal config file exposed
//	    category: secrets
//	    severity: high
//	    body_regex: 'MYCORP_TOKEN='
//
//	tls:
//	  - vendor: MyCorp
//	    product: Internal Cloud
//	    category: hosting
//	    patterns:
//	      - name: mycorp-cloud
//	        san_suffix: .mycorp.io
//	        kind: san-suffix
//	        confidence: high
//
// The loader is read-only: it never writes the YAML, never reaches
// network. A malformed file is rejected at load time so a typo
// cannot silently void detection during a scan.
package customcatalog

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/apifingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/filefingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/headerfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/jsfingerprint"
	"github.com/vulnertrack/kite-collector/internal/discovery/network/tlsfingerprint"
)

// Overlay is the parsed YAML form, one entry per fingerprint package.
type Overlay struct {
	API    []apiSigYAML    `yaml:"api"`
	Header []headerSigYAML `yaml:"header"`
	JS     []jsSigYAML     `yaml:"js"`
	File   []fileProbeYAML `yaml:"file"`
	TLS    []tlsSigYAML    `yaml:"tls"`
}

// Catalogs holds the five compiled catalog slices ready to append to
// each package's DefaultCatalog().
type Catalogs struct {
	API    []apifingerprint.Signature
	Header []headerfingerprint.Signature
	JS     []jsfingerprint.Signature
	File   []filefingerprint.Probe
	TLS    []tlsfingerprint.Signature
}

// LoadFile parses path and returns compiled catalogs. A missing file
// is not an error — the caller gets an empty Catalogs back so the
// "overlay is optional" call site stays simple. Other errors (parse,
// validation, regex compile) are surfaced verbatim.
func LoadFile(path string) (Catalogs, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path from operator config
	if err != nil {
		if os.IsNotExist(err) {
			return Catalogs{}, nil
		}
		return Catalogs{}, fmt.Errorf("customcatalog: read %s: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses a YAML overlay from memory. Tests use this; the
// CLI normally goes through LoadFile.
func LoadBytes(data []byte) (Catalogs, error) {
	var ov Overlay
	if err := yaml.Unmarshal(data, &ov); err != nil {
		return Catalogs{}, fmt.Errorf("customcatalog: yaml: %w", err)
	}
	return compile(ov)
}

func compile(ov Overlay) (Catalogs, error) {
	out := Catalogs{}

	for i, s := range ov.API {
		sig, err := s.compile()
		if err != nil {
			return out, fmt.Errorf("api[%d] %s/%s: %w", i, s.Vendor, s.Product, err)
		}
		out.API = append(out.API, sig)
	}
	for i, s := range ov.Header {
		sig, err := s.compile()
		if err != nil {
			return out, fmt.Errorf("header[%d] %s/%s: %w", i, s.Vendor, s.Product, err)
		}
		out.Header = append(out.Header, sig)
	}
	for i, s := range ov.JS {
		sig, err := s.compile()
		if err != nil {
			return out, fmt.Errorf("js[%d] %s/%s: %w", i, s.Vendor, s.Product, err)
		}
		out.JS = append(out.JS, sig)
	}
	for i, p := range ov.File {
		probe, err := p.compile()
		if err != nil {
			return out, fmt.Errorf("file[%d] %s: %w", i, p.Path, err)
		}
		out.File = append(out.File, probe)
	}
	for i, s := range ov.TLS {
		sig, err := s.compile()
		if err != nil {
			return out, fmt.Errorf("tls[%d] %s/%s: %w", i, s.Vendor, s.Product, err)
		}
		out.TLS = append(out.TLS, sig)
	}
	return out, nil
}

// ---------------------------------------------------------------
// API
// ---------------------------------------------------------------

type apiSigYAML struct {
	Vendor     string        `yaml:"vendor"`
	Product    string        `yaml:"product"`
	Category   string        `yaml:"category"`
	Confidence string        `yaml:"confidence"`
	Probes     []apiProbeYAML `yaml:"probes"`
}

type apiProbeYAML struct {
	Path           string `yaml:"path"`
	ExpectedStatus []int  `yaml:"expected_status"`
	BodyContains   string `yaml:"body_contains"`
	BodyRegex      string `yaml:"body_regex"`
	HeaderName     string `yaml:"header_name"`
	HeaderRegex    string `yaml:"header_regex"`
}

func (s apiSigYAML) compile() (apifingerprint.Signature, error) {
	if s.Vendor == "" || s.Product == "" {
		return apifingerprint.Signature{}, errors.New("vendor and product required")
	}
	out := apifingerprint.Signature{
		Vendor:     s.Vendor,
		Product:    s.Product,
		Category:   apifingerprint.Category(s.Category),
		Confidence: apifingerprint.Confidence(s.Confidence),
	}
	for j, p := range s.Probes {
		if p.Path == "" || p.Path[0] != '/' {
			return out, fmt.Errorf("probe[%d]: path must start with /", j)
		}
		probe := apifingerprint.Probe{
			Path:           p.Path,
			ExpectedStatus: p.ExpectedStatus,
			BodyContains:   p.BodyContains,
			HeaderName:     p.HeaderName,
		}
		if p.BodyRegex != "" {
			re, err := regexp.Compile(p.BodyRegex)
			if err != nil {
				return out, fmt.Errorf("probe[%d]: body_regex: %w", j, err)
			}
			probe.BodyRegex = re
		}
		if p.HeaderRegex != "" {
			re, err := regexp.Compile(p.HeaderRegex)
			if err != nil {
				return out, fmt.Errorf("probe[%d]: header_regex: %w", j, err)
			}
			probe.HeaderRegex = re
		}
		if !probe.HasMatcher() {
			return out, fmt.Errorf("probe[%d]: at least one of body_contains/body_regex/header_name required", j)
		}
		out.Probes = append(out.Probes, probe)
	}
	return out, nil
}

// ---------------------------------------------------------------
// Header
// ---------------------------------------------------------------

type headerSigYAML struct {
	Vendor   string             `yaml:"vendor"`
	Product  string             `yaml:"product"`
	Category string             `yaml:"category"`
	Patterns []headerPatternYAML `yaml:"patterns"`
}

type headerPatternYAML struct {
	Name          string `yaml:"name"`
	HeaderName    string `yaml:"header_name"`
	ValueRegex    string `yaml:"value_regex"`
	ValueContains string `yaml:"value_contains"`
	CookieName    string `yaml:"cookie_name"`
	Kind          string `yaml:"kind"`
	Confidence    string `yaml:"confidence"`
}

func (s headerSigYAML) compile() (headerfingerprint.Signature, error) {
	if s.Vendor == "" || s.Product == "" {
		return headerfingerprint.Signature{}, errors.New("vendor and product required")
	}
	out := headerfingerprint.Signature{
		Vendor:   s.Vendor,
		Product:  s.Product,
		Category: headerfingerprint.Category(s.Category),
	}
	for j, p := range s.Patterns {
		if p.Name == "" {
			return out, fmt.Errorf("pattern[%d]: name required", j)
		}
		if (p.HeaderName == "") == (p.CookieName == "") {
			return out, fmt.Errorf("pattern[%d]: exactly one of header_name or cookie_name required", j)
		}
		pat := headerfingerprint.Pattern{
			Name:          p.Name,
			HeaderName:    p.HeaderName,
			ValueContains: p.ValueContains,
			CookieName:    p.CookieName,
			Kind:          headerfingerprint.SignalKind(p.Kind),
			Confidence:    headerfingerprint.Confidence(p.Confidence),
		}
		if p.ValueRegex != "" {
			re, err := regexp.Compile(p.ValueRegex)
			if err != nil {
				return out, fmt.Errorf("pattern[%d]: value_regex: %w", j, err)
			}
			pat.ValueRegex = re
		}
		out.Patterns = append(out.Patterns, pat)
	}
	return out, nil
}

// ---------------------------------------------------------------
// JS
// ---------------------------------------------------------------

type jsSigYAML struct {
	Vendor   string         `yaml:"vendor"`
	Product  string         `yaml:"product"`
	Category string         `yaml:"category"`
	Patterns []jsPatternYAML `yaml:"patterns"`
}

type jsPatternYAML struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	Kind       string `yaml:"kind"`
	Confidence string `yaml:"confidence"`
}

func (s jsSigYAML) compile() (jsfingerprint.Signature, error) {
	if s.Vendor == "" || s.Product == "" {
		return jsfingerprint.Signature{}, errors.New("vendor and product required")
	}
	out := jsfingerprint.Signature{
		Vendor:   s.Vendor,
		Product:  s.Product,
		Category: jsfingerprint.Category(s.Category),
	}
	for j, p := range s.Patterns {
		if p.Name == "" {
			return out, fmt.Errorf("pattern[%d]: name required", j)
		}
		if p.Regex == "" {
			return out, fmt.Errorf("pattern[%d]: regex required", j)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return out, fmt.Errorf("pattern[%d]: regex: %w", j, err)
		}
		out.Patterns = append(out.Patterns, jsfingerprint.Pattern{
			Name:       p.Name,
			Regex:      re,
			Kind:       jsfingerprint.SignalKind(p.Kind),
			Confidence: jsfingerprint.Confidence(p.Confidence),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------
// File
// ---------------------------------------------------------------

type fileProbeYAML struct {
	Path           string `yaml:"path"`
	Description    string `yaml:"description"`
	Category       string `yaml:"category"`
	Severity       string `yaml:"severity"`
	ExpectedStatus []int  `yaml:"expected_status"`
	BodyContains   string `yaml:"body_contains"`
	BodyRegex      string `yaml:"body_regex"`
	MustNotContain string `yaml:"must_not_contain"`
}

func (p fileProbeYAML) compile() (filefingerprint.Probe, error) {
	if p.Path == "" || p.Path[0] != '/' {
		return filefingerprint.Probe{}, errors.New("path must start with /")
	}
	if p.Description == "" {
		return filefingerprint.Probe{}, errors.New("description required")
	}
	probe := filefingerprint.Probe{
		Path:           p.Path,
		Description:    p.Description,
		Category:       filefingerprint.Category(p.Category),
		Severity:       filefingerprint.Severity(p.Severity),
		ExpectedStatus: p.ExpectedStatus,
		BodyContains:   p.BodyContains,
		MustNotContain: p.MustNotContain,
	}
	if p.BodyRegex != "" {
		re, err := regexp.Compile(p.BodyRegex)
		if err != nil {
			return probe, fmt.Errorf("body_regex: %w", err)
		}
		probe.BodyRegex = re
	}
	return probe, nil
}

// ---------------------------------------------------------------
// TLS
// ---------------------------------------------------------------

type tlsSigYAML struct {
	Vendor   string          `yaml:"vendor"`
	Product  string          `yaml:"product"`
	Category string          `yaml:"category"`
	Patterns []tlsPatternYAML `yaml:"patterns"`
}

type tlsPatternYAML struct {
	Name         string `yaml:"name"`
	SANSuffix    string `yaml:"san_suffix"`
	IssuerRegex  string `yaml:"issuer_regex"`
	SubjectRegex string `yaml:"subject_regex"`
	OCSPHost     string `yaml:"ocsp_host"`
	Kind         string `yaml:"kind"`
	Confidence   string `yaml:"confidence"`
}

func (s tlsSigYAML) compile() (tlsfingerprint.Signature, error) {
	if s.Vendor == "" || s.Product == "" {
		return tlsfingerprint.Signature{}, errors.New("vendor and product required")
	}
	out := tlsfingerprint.Signature{
		Vendor:   s.Vendor,
		Product:  s.Product,
		Category: tlsfingerprint.Category(s.Category),
	}
	for j, p := range s.Patterns {
		if p.Name == "" {
			return out, fmt.Errorf("pattern[%d]: name required", j)
		}
		matcherCount := 0
		if p.SANSuffix != "" {
			matcherCount++
		}
		if p.IssuerRegex != "" {
			matcherCount++
		}
		if p.SubjectRegex != "" {
			matcherCount++
		}
		if p.OCSPHost != "" {
			matcherCount++
		}
		if matcherCount != 1 {
			return out, fmt.Errorf("pattern[%d]: exactly one of san_suffix/issuer_regex/subject_regex/ocsp_host required", j)
		}
		pat := tlsfingerprint.Pattern{
			Name:       p.Name,
			SANSuffix:  p.SANSuffix,
			OCSPHost:   p.OCSPHost,
			Kind:       tlsfingerprint.SignalKind(p.Kind),
			Confidence: tlsfingerprint.Confidence(p.Confidence),
		}
		if p.IssuerRegex != "" {
			re, err := regexp.Compile(p.IssuerRegex)
			if err != nil {
				return out, fmt.Errorf("pattern[%d]: issuer_regex: %w", j, err)
			}
			pat.IssuerRegex = re
		}
		if p.SubjectRegex != "" {
			re, err := regexp.Compile(p.SubjectRegex)
			if err != nil {
				return out, fmt.Errorf("pattern[%d]: subject_regex: %w", j, err)
			}
			pat.SubjectRegex = re
		}
		out.Patterns = append(out.Patterns, pat)
	}
	return out, nil
}

// ---------------------------------------------------------------
// Merge helpers
// ---------------------------------------------------------------

// MergeAPI appends the custom signatures to the supplied base catalog.
// Equivalents for the other packages follow the same shape.
func MergeAPI(base, custom []apifingerprint.Signature) []apifingerprint.Signature {
	out := make([]apifingerprint.Signature, 0, len(base)+len(custom))
	out = append(out, base...)
	out = append(out, custom...)
	return out
}

// MergeHeader merges custom into base.
func MergeHeader(base, custom []headerfingerprint.Signature) []headerfingerprint.Signature {
	out := make([]headerfingerprint.Signature, 0, len(base)+len(custom))
	out = append(out, base...)
	out = append(out, custom...)
	return out
}

// MergeJS merges custom into base.
func MergeJS(base, custom []jsfingerprint.Signature) []jsfingerprint.Signature {
	out := make([]jsfingerprint.Signature, 0, len(base)+len(custom))
	out = append(out, base...)
	out = append(out, custom...)
	return out
}

// MergeFile merges custom into base.
func MergeFile(base, custom []filefingerprint.Probe) []filefingerprint.Probe {
	out := make([]filefingerprint.Probe, 0, len(base)+len(custom))
	out = append(out, base...)
	out = append(out, custom...)
	return out
}

// MergeTLS merges custom into base.
func MergeTLS(base, custom []tlsfingerprint.Signature) []tlsfingerprint.Signature {
	out := make([]tlsfingerprint.Signature, 0, len(base)+len(custom))
	out = append(out, base...)
	out = append(out, custom...)
	return out
}
