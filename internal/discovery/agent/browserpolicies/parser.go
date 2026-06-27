package browserpolicies

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseChromeFamilyPolicy walks one Chrome / Edge managed-policy
// JSON file and emits one Policy per top-level key. The shape is a
// flat object: `{"PasswordManagerEnabled": true, "URLBlocklist": [...]}`.
// Nested objects (rare) become an opaque JSON string in PolicyValue.
//
// `browser` lets Chrome and Edge share this code path since the
// vendor delivers the same JSON grammar. The Policy.BrowserKind is
// stamped from the caller.
func ParseChromeFamilyPolicy(body []byte, filePath string, browser BrowserKind) ([]Policy, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty policy file")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	hash := HashContents(body)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal chrome-family json: %w", err)
	}

	out := make([]Policy, 0, len(raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		p := Policy{
			BrowserKind: browser,
			FilePath:    filePath,
			FileHash:    hash,
			PolicyName:  k,
		}
		p.PolicyValueKind, p.PolicyValue = classifyJSON(raw[k])
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxRows {
			break
		}
	}
	return out, nil
}

// ParseFirefoxPolicy walks one Firefox `policies.json` body. The
// shape wraps a `policies` object: `{"policies": {"DisableSafeBrowsing": true}}`.
// We emit one Policy per inner key. Optional top-level wrapper-
// less files are also accepted (some MDM tools omit the wrapper).
func ParseFirefoxPolicy(body []byte, filePath string) ([]Policy, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty policy file")
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	hash := HashContents(body)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal firefox json: %w", err)
	}

	// Unwrap the `policies` wrapper if present.
	if wrapped, ok := raw["policies"]; ok {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(wrapped, &inner); err != nil {
			return nil, fmt.Errorf("unmarshal policies wrapper: %w", err)
		}
		raw = inner
	}

	out := make([]Policy, 0, len(raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		p := Policy{
			BrowserKind: BrowserFirefox,
			FilePath:    filePath,
			FileHash:    hash,
			PolicyName:  k,
		}
		p.PolicyValueKind, p.PolicyValue = classifyJSON(raw[k])
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxRows {
			break
		}
	}
	return out, nil
}

// classifyJSON tags a JSON value with its kind and returns a
// canonical string form. Booleans, numbers, and nulls return the
// raw token; strings return the quoted form stripped of quotes;
// arrays and objects return their compact JSON form so the audit
// pipeline can grep them.
func classifyJSON(raw json.RawMessage) (PolicyValueKind, string) {
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "null" {
		return KindNull, "null"
	}
	switch v[0] {
	case 't', 'T':
		return KindBool, "true"
	case 'f', 'F':
		return KindBool, "false"
	case '"':
		// String — strip outer quotes.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return KindString, s
		}
		return KindString, v
	case '[':
		// Compact array.
		return KindArray, compactJSON(raw)
	case '{':
		return KindObject, compactJSON(raw)
	default:
		// Number (could be negative, fraction, scientific).
		return KindNumber, v
	}
}

// compactJSON returns a single-line, compact form of any JSON
// value. Used so array/object PolicyValue strings stay grep-able
// regardless of input formatting.
func compactJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}
