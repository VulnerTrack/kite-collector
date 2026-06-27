package sqlite

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogCodes_FollowConvention pins the `sqlitestore.<surface>.<event>`
// shape so a future contributor can't accidentally ship a code that
// breaks downstream Loki/Splunk filters. Every code MUST:
//   - have at least 3 dot-separated segments
//   - lead with the literal "sqlitestore" namespace (NOT the bare package
//     name "sqlite" — that word is ambiguous in cross-tenant log indexes)
//   - use snake_case lowercase for surface and event
func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodePreflightSyncVolume, LogCodePreflightUNCShare, LogCodePreflightNonLocalFS,
		LogCodeEncryptedUsingRAMDir, LogCodeEncryptedNoRAMDir, LogCodeEncryptedNoTempDir,
		LogCodeEncryptedWeakKeyBackend,
		LogCodeEncryptedDecrypting, LogCodeEncryptedMigratingUnencrypted,
		LogCodeEncryptedEncryptingAtRest,
		LogCodeEncryptedRemoveWorkingFile, LogCodeEncryptedRemoveWorkdir,
		LogCodeMigrateChecksumMismatch, LogCodeMigrateApplying,
		LogCodeMigrateColumnExists, LogCodeMigrateApplied, LogCodeMigrateEntryRemoved,
	}

	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have at least 3 dot-separated segments (namespace.surface.event)", s)
			assert.Equal(t, "sqlitestore", parts[0],
				"code %q must lead with the sqlitestore namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase for grep-friendliness", s)
			assert.NotContains(t, s, " ",
				"code %q must not contain spaces — use underscores between words", s)
		})
	}
}

// TestLogCodes_AreUnique pins the no-duplicate-code rule. Two log call
// sites sharing the same code would make downstream alerts ambiguous
// about which surface actually fired.
func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	all := []LogCode{
		LogCodePreflightSyncVolume, LogCodePreflightUNCShare, LogCodePreflightNonLocalFS,
		LogCodeEncryptedUsingRAMDir, LogCodeEncryptedNoRAMDir, LogCodeEncryptedNoTempDir,
		LogCodeEncryptedWeakKeyBackend,
		LogCodeEncryptedDecrypting, LogCodeEncryptedMigratingUnencrypted,
		LogCodeEncryptedEncryptingAtRest,
		LogCodeEncryptedRemoveWorkingFile, LogCodeEncryptedRemoveWorkdir,
		LogCodeMigrateChecksumMismatch, LogCodeMigrateApplying,
		LogCodeMigrateColumnExists, LogCodeMigrateApplied, LogCodeMigrateEntryRemoved,
	}
	for _, c := range all {
		assert.False(t, seen[c],
			"duplicate log code %q — every call site must have a unique identifier", string(c))
		seen[c] = true
	}
}
