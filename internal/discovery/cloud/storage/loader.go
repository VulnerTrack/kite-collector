package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SignatureSpec is the on-disk representation of a Signature. Patterns are
// stored as strings (compiled at load time) and CIDRs as text. The struct
// is the contract analysts edit; LoadSignaturesFromFile validates it and
// produces compiled storage.Signature values.
type SignatureSpec struct {
	Provider    string   `json:"provider" yaml:"provider"`
	Signal      string   `json:"signal" yaml:"signal"`
	Pattern     string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Description string   `json:"description" yaml:"description"`
	Literals    []string `json:"literals,omitempty" yaml:"literals,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
	Confidence  uint8    `json:"confidence" yaml:"confidence"`
}

// validSignalTypes is the closed set of signal values an external file may
// declare. Keeping this enforced lets the detector switch statement stay
// closed without surprising bypasses.
var validSignalTypes = map[SignalType]struct{}{
	SignalFile:    {},
	SignalTLS:     {},
	SignalJA4:     {},
	SignalJA4S:    {},
	SignalJA4H:    {},
	SignalJA5:     {},
	SignalAPI:     {},
	SignalNetwork: {},
	SignalBucket:  {},
}

// LoadSignaturesFromFile reads path, detects its format from the extension
// (.json, .yaml, .yml), and returns compiled signatures. Errors include the
// file path and a 1-based index of the offending spec to keep operator
// debugging cheap.
func LoadSignaturesFromFile(path string) ([]Signature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signature file %s: %w", path, err)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return ParseSignaturesJSON(data)
	case ".yaml", ".yml":
		return ParseSignaturesYAML(data)
	default:
		return nil, fmt.Errorf("signature file %s: unsupported extension (want .json/.yaml/.yml)", path)
	}
}

// ParseSignaturesJSON decodes a JSON document containing either a top-level
// array of SignatureSpec or an object with a "signatures" key. Both shapes
// are accepted so operators can wrap the list with metadata if they prefer.
func ParseSignaturesJSON(data []byte) ([]Signature, error) {
	specs, err := decodeSpecs(data, func(b []byte, v any) error { return json.Unmarshal(b, v) })
	if err != nil {
		return nil, fmt.Errorf("parse JSON signatures: %w", err)
	}
	return compileSpecs(specs)
}

// ParseSignaturesYAML mirrors ParseSignaturesJSON for YAML.
func ParseSignaturesYAML(data []byte) ([]Signature, error) {
	specs, err := decodeSpecs(data, func(b []byte, v any) error { return yaml.Unmarshal(b, v) })
	if err != nil {
		return nil, fmt.Errorf("parse YAML signatures: %w", err)
	}
	return compileSpecs(specs)
}

// decodeSpecs handles both the array and object shapes. It first tries the
// wrapped object {"signatures": [...]}; if that fails to populate the
// slice, it falls back to a bare array.
func decodeSpecs(data []byte, decode func([]byte, any) error) ([]SignatureSpec, error) {
	var wrapped struct {
		Signatures []SignatureSpec `json:"signatures" yaml:"signatures"`
	}
	if err := decode(data, &wrapped); err == nil && len(wrapped.Signatures) > 0 {
		return wrapped.Signatures, nil
	}
	var bare []SignatureSpec
	if err := decode(data, &bare); err != nil {
		return nil, err
	}
	if len(bare) == 0 {
		return nil, errors.New("no signatures found (expected an array or a {signatures: [...]} object)")
	}
	return bare, nil
}

// compileSpecs validates each SignatureSpec and turns it into a storage.Signature.
// All errors include the 1-based index of the bad spec.
func compileSpecs(specs []SignatureSpec) ([]Signature, error) {
	out := make([]Signature, 0, len(specs))
	for i, spec := range specs {
		sig, err := compileSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("signature[%d]: %w", i+1, err)
		}
		out = append(out, sig)
	}
	return out, nil
}

// compileSpec validates one spec and returns the compiled form. Required:
// Provider, Signal, Description, and at least one of Pattern/Literals/CIDRs.
// Confidence defaults to medium (2) when zero so analysts don't have to
// remember to fill it in for every entry.
func compileSpec(spec SignatureSpec) (Signature, error) {
	if spec.Provider == "" {
		return Signature{}, errors.New("provider is required")
	}
	if spec.Signal == "" {
		return Signature{}, errors.New("signal is required")
	}
	signal := SignalType(spec.Signal)
	if _, ok := validSignalTypes[signal]; !ok {
		return Signature{}, fmt.Errorf("unknown signal %q (want file,tls,ja4,ja4s,ja4h,ja5,api,network,bucket)", spec.Signal)
	}
	if spec.Description == "" {
		return Signature{}, errors.New("description is required")
	}
	if spec.Pattern == "" && len(spec.Literals) == 0 && len(spec.CIDRs) == 0 {
		return Signature{}, errors.New("at least one of pattern, literals, or cidrs is required")
	}
	if signal == SignalNetwork && len(spec.CIDRs) == 0 {
		return Signature{}, errors.New("signal=network requires cidrs")
	}

	var pat *regexp.Regexp
	if spec.Pattern != "" {
		compiled, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return Signature{}, fmt.Errorf("compile pattern %q: %w", spec.Pattern, err)
		}
		pat = compiled
	}
	for _, cidr := range spec.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return Signature{}, fmt.Errorf("invalid cidr %q: %w", cidr, err)
		}
	}

	conf := Confidence(spec.Confidence)
	if conf == 0 {
		conf = ConfidenceMedium
	}
	if conf > ConfidenceHigh {
		return Signature{}, fmt.Errorf("confidence %d out of range (want 1-3)", spec.Confidence)
	}

	return Signature{
		Provider:    Provider(spec.Provider),
		Signal:      signal,
		Pattern:     pat,
		Literals:    append([]string(nil), spec.Literals...),
		CIDRs:       append([]string(nil), spec.CIDRs...),
		Description: spec.Description,
		Confidence:  conf,
	}, nil
}

// MergedCatalogue returns the built-in catalogue concatenated with extra
// signatures (typically from LoadSignaturesFromFile). The built-in entries
// come first so external overrides do not silently win on tied lookups.
func MergedCatalogue(extra []Signature) []Signature {
	out := make([]Signature, 0, len(catalogue)+len(extra))
	out = append(out, catalogue...)
	out = append(out, extra...)
	return out
}
