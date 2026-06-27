package sqlite

import (
	"strings"
	"testing"
)

// FuzzMigrate_NameValidation_DoesNotPanic exercises the migration filename
// validator (migrationNameRe) and the version-derivation step on arbitrary
// input strings. The migration runner reads filenames from an embedded FS
// and rejects anything that doesn't match the YYYYMMDDHHMMSS_ convention;
// hostile filenames must be rejected without crashing the binary.
//
// We fuzz the in-package primitives directly because the public Migrate()
// reads from the embedded FS and cannot be steered from a test. This still
// gives meaningful coverage: every filename passing the regex feeds straight
// into version-derivation and SHA256 checksumming, which are the next
// failure surfaces in the migration pipeline.
//
// Errors / mismatches are FINE — only panics fail the test.
func FuzzMigrate_NameValidation_DoesNotPanic(f *testing.F) {
	// Valid timestamps.
	f.Add("20260403000000_initial.sql")
	f.Add("20991231235959_future.sql")
	// Invalid shapes.
	f.Add("foo.sql")
	f.Add("2026-04-24_foo.sql")
	f.Add("_foo.sql")
	f.Add("")
	// Path traversal probes — the regex must reject these.
	f.Add("..")
	f.Add("../../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("20260403000000_../../etc/passwd.sql")
	// Embedded null byte (would terminate C strings if the parser slipped
	// into unsafe territory).
	f.Add("20260403000000_\x00danger.sql")
	// Pathologically long.
	long := make([]byte, 8192)
	for i := range long {
		long[i] = 'A'
	}
	f.Add("20260403000000_" + string(long) + ".sql")
	// Unicode + invalid UTF-8.
	f.Add("20260403000000_\xff\xfe\xfd.sql")
	f.Add("20260403000000_\xed\xa0\x80.sql") // lone high surrogate

	f.Fuzz(func(t *testing.T, name string) {
		// 1. Regex match — the gatekeeper for embedded migration files.
		matched := migrationNameRe.MatchString(name)

		// 2. Version derivation runs unconditionally inside listMigrationFiles
		//    after the regex passes; mirror that here so the fuzzer covers it.
		version := strings.TrimSuffix(name, ".sql")

		// 3. Checksum computation must be panic-free on any byte content.
		//    sha256hex is exercised on file *content*, but content is also
		//    attacker-controlled in adversarial scenarios — feed the fuzzed
		//    name bytes through it as a cheap panic probe.
		sum := sha256hex([]byte(name))

		// Defensive sanity: a successful match implies length >= 15
		// (14 digits + underscore). If the regex ever drifts to allow
		// shorter inputs, version derivation could slice into nothing —
		// we'd rather catch that here than at runtime.
		if matched && len(name) < 15 {
			t.Fatalf("regex matched a sub-15-char name %q (version=%q)", name, version)
		}
		// sha256hex always returns 64 hex chars; a deviation indicates
		// an internal change worth flagging.
		if len(sum) != 64 {
			t.Fatalf("sha256hex returned %d chars, want 64", len(sum))
		}
	})
}
