package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadConfig_DoesNotPanic feeds arbitrary YAML byte input to Load via a
// tmp file and asserts no panic. Errors are FINE — most fuzz inputs will be
// malformed YAML; the test only fails if the loader crashes the process.
//
// The seed corpus pins real-world shapes (full config, minimal config,
// anchors/aliases, type-confusion booleans) so they execute as deterministic
// asserts on every `go test ./...`.
func FuzzLoadConfig_DoesNotPanic(f *testing.F) {
	// Valid full-ish config.
	f.Add([]byte(`
log_level: info
output_format: table
data_dir: /tmp/kite
stale_threshold: 24h
discovery:
  sources:
    agent:
      enabled: true
      collect_software: true
streaming:
  interval: 6h
  otlp:
    endpoint: https://otel.example.com
    protocol: http
`))
	// Minimal config — exercises defaulting paths.
	f.Add([]byte("log_level: debug\n"))
	// Empty file.
	f.Add([]byte(""))
	// Anchors and aliases (YAML feature historically associated with
	// billion-laughs DoS in unsafe parsers).
	f.Add([]byte(`
defaults: &defaults
  enabled: true
  timeout: 5s
discovery:
  sources:
    agent: *defaults
    docker: *defaults
`))
	// Deeply nested.
	f.Add([]byte(`
a:
  b:
    c:
      d:
        e:
          f: deep
`))
	// Bool/int/string confusion in fields the loader expects typed.
	f.Add([]byte(`
log_level: 1
metrics:
  enabled: "true"
  listen: 9090
`))
	// Unicode in keys + values.
	f.Add([]byte("\xe2\x9c\x93key: \xe2\x9c\x93value\n"))
	// Pathologically long key.
	const longKeyLen = 4096
	suffix := []byte(": value\n")
	long := make([]byte, longKeyLen, longKeyLen+len(suffix))
	for i := range long {
		long[i] = 'k'
	}
	f.Add(append(long, suffix...))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "kite.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write tmp config: %v", err)
		}

		// We discard the result + error: a panic is the only failure mode.
		_, _ = Load(path)
	})
}
