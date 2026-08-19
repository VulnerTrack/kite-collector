package vpn

import (
	"os"
	"os/exec"
	"strings"
)

// defaultLookPath is the production binary resolver.
func defaultLookPath(name string) (string, error) { return exec.LookPath(name) }

// defaultGetenv is the production env reader. Enumerators route env access
// through a seam so tests set credentials/config without os.Setenv races
// across parallel tests.
func defaultGetenv(key string) string { return os.Getenv(key) }

// firstNonEmpty returns the first non-blank argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// toStr coerces an untyped config value to a trimmed string, or "".
func toStr(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// truncate caps a string to n bytes for safe inclusion in an error/log.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// notDisabled reports whether the source-level config permits this source
// to run. VPN host discovery is a LOCAL, read-only source (like the agent
// and network sources) and therefore runs by default: only an explicit
// `enabled: false` in discovery.sources.vpn turns it off. A nil or absent
// config means "not mentioned in YAML", which still runs — unlike a vendor
// API connector, a local enumeration has no credential to gate on.
func notDisabled(cfg map[string]any) bool {
	if v, ok := cfg["enabled"].(bool); ok {
		return v
	}
	return true
}
