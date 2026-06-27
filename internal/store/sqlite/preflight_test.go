package sqlite

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newWarnLogger returns a slog.Logger that captures records into buf at
// the WARN level. Lower levels are still recorded so tests can assert
// silence too.
func newWarnLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func TestWarnIfPathIsSuspect_FlagsCloudSyncFolders(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool // expect a warning
	}{
		// Suspect cloud-sync folders.
		{"dropbox", "/home/alice/Dropbox/kite-collector/kite.db", true},
		{"onedrive", "/home/alice/OneDrive/kite.db", true},
		{"google_drive", "/home/alice/Google Drive/kite.db", true},
		{"icloud_macos", "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/kite.db", true},
		{"sync_folder", "/home/alice/Sync/kite-collector/kite.db", true},
		{"syncthing", "/home/alice/Syncthing/db/kite.db", true},
		{"box", "/home/alice/Box/agents/kite.db", true},
		{"pcloud", "/home/alice/pCloudDrive/kite.db", true},
		{"mega", "/home/alice/MEGA/kite.db", true},
		{"nextcloud", "/home/alice/Nextcloud/kite.db", true},
		{"owncloud", "/home/alice/ownCloud/kite.db", true},
		{"yandex", "/home/alice/Yandex.Disk/kite.db", true},

		// Clean local paths.
		{"local_home", "/home/alice/.local/share/kite-collector/kite.db", false},
		{"local_var", "/var/lib/kite-collector/kite.db", false},
		{"tmp", "/tmp/kite.db", false},
		{"relative", "./kite.db", false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			WarnIfPathIsSuspect(newWarnLogger(&buf), tc.path)

			out := buf.String()
			contains := strings.Contains(out, `"level":"WARN"`) &&
				strings.Contains(out, "sync/network volume") ||
				strings.Contains(out, "UNC/SMB share") ||
				strings.Contains(out, "non-local filesystem")

			if tc.want {
				assert.True(t, contains, "expected a warn for %q, got: %s", tc.path, out)
			} else {
				assert.NotContains(t, out, `"level":"WARN"`,
					"did not expect a warn for %q, got: %s", tc.path, out)
			}
		})
	}
}

func TestWarnIfPathIsSuspect_NilLoggerUsesDefault(t *testing.T) {
	// Should not panic.
	require.NotPanics(t, func() {
		WarnIfPathIsSuspect(nil, "/var/lib/kite-collector/kite.db")
	})
}

func TestWarnIfPathIsSuspect_HintMentionsRemediation(t *testing.T) {
	var buf bytes.Buffer
	WarnIfPathIsSuspect(newWarnLogger(&buf), "/home/alice/Dropbox/kite.db")
	out := buf.String()
	require.Contains(t, out, "hint")
	assert.Contains(t, out, "local drive")
}

func TestLookupMountFSType_GracefullyHandlesMissingProc(t *testing.T) {
	// On non-Linux systems /proc/self/mountinfo doesn't exist; on Linux
	// it does but the path may not match anything outside / in tmpfs
	// tests. Either way the function must never panic.
	_, _, _ = lookupMountFSType(filepath.Join(t.TempDir(), "kite.db"))
}
