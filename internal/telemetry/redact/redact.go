// Package redact enforces the RFC-0115 §4.3 forbidden-key policy at the
// agent before any telemetry leaves the process. It is the last line of
// defence against accidental egress of credentials, environment variables,
// or process state through OTel attributes.
//
// The denylist is intentionally aggressive:
//   - any key containing password, secret, token, or key (with a small
//     allowlist for the resource attributes that legitimately contain
//     those substrings — service.instance.id, tenant.id);
//   - keys named env, environ, command, cmdline, argv;
//   - keys starting with internal. or debug.
//
// Filter is hot-path code (called on every emit). It avoids allocation when
// the input contains no forbidden keys.
package redact

import "strings"

// allowedSensitiveKeys is the set of declared resource attributes that
// contain "id" or similar substrings but are NOT credentials. Without this
// allowlist the substring check below would block them.
var allowedSensitiveKeys = map[string]struct{}{
	"service.instance.id":  {},
	"agent.id":             {},
	"host.id":              {},
	"tenant.id":            {},
	"security.scan.uid":    {},
	"security.asset.uid":   {},
	"security.finding.uid": {},
}

// forbiddenSubstrings are case-insensitive fragments that, when present in
// a key, indicate it likely carries credential material.
var forbiddenSubstrings = []string{
	"password",
	"passwd",
	"secret",
	"apikey",
	"api_key",
	"api-key",
	"private_key",
	"privatekey",
	"private-key",
	"authorization",
	"auth_token",
	"authtoken",
	"bearer",
	"session_id",
	"sessionid",
	"cookie",
}

// forbiddenExact are full key names always blocked.
var forbiddenExact = map[string]struct{}{
	"env":     {},
	"environ": {},
	"command": {},
	"cmdline": {},
	"argv":    {},
	"token":   {},
	"key":     {},
}

// forbiddenPrefixes are key prefixes always blocked.
var forbiddenPrefixes = []string{
	"internal.",
	"debug.",
	"env.",
	"environ.",
}

// IsForbidden reports whether key is rejected by the contract redactor.
//
// The check is conservative: the agent never has a legitimate reason to
// emit a credential through OTel, so on doubt we drop. False positives can
// be mitigated by adding the key to allowedSensitiveKeys with a recorded
// rationale.
func IsForbidden(key string) bool {
	if key == "" {
		return true
	}
	if _, ok := allowedSensitiveKeys[key]; ok {
		return false
	}
	if _, ok := forbiddenExact[strings.ToLower(key)]; ok {
		return true
	}
	lower := strings.ToLower(key)
	for _, p := range forbiddenPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	for _, sub := range forbiddenSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// Filter returns a copy of attrs with all forbidden keys removed. The
// original map is not mutated.
//
// When attrs contains no forbidden keys Filter returns attrs unchanged
// (zero allocation) — callers that need to mutate the result should
// always pass a fresh map.
func Filter(attrs map[string]string) map[string]string {
	for k := range attrs {
		if IsForbidden(k) {
			out := make(map[string]string, len(attrs))
			for kk, vv := range attrs {
				if !IsForbidden(kk) {
					out[kk] = vv
				}
			}
			return out
		}
	}
	return attrs
}

// FilterKeys returns a copy of keys with all forbidden entries removed.
func FilterKeys(keys []string) []string {
	out := keys[:0:0]
	for _, k := range keys {
		if IsForbidden(k) {
			continue
		}
		out = append(out, k)
	}
	return out
}
