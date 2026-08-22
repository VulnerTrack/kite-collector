package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPackagedUnitInSyncWithAUR guards the "keep the two in sync" comment
// in packaging/systemd/kite-collector.service: the deb/rpm unit and the
// AUR package's unit (sibling repo kite-collector-aur) must agree on every
// directive — comments may differ, behavior may not. The AUR repo is a
// sibling checkout on dev machines; when it is absent (isolated CI
// checkout) the test skips rather than fails.
func TestPackagedUnitInSyncWithAUR(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	debUnit := filepath.Join(repoRoot, "packaging", "systemd", "kite-collector.service")
	aurUnit := filepath.Join(repoRoot, "..", "kite-collector-aur", "kite-collector.service")

	debData, err := os.ReadFile(debUnit) //#nosec G304 -- repo-relative fixture
	require.NoError(t, err, "the deb/rpm unit must exist in this repo")

	aurData, err := os.ReadFile(aurUnit) //#nosec G304 -- sibling-repo fixture
	if err != nil {
		t.Skipf("AUR sibling repo not checked out (%v) — sync check runs on dev machines", err)
	}

	assert.Equal(t, unitDirectives(string(aurData)), unitDirectives(string(debData)),
		"deb/rpm unit (packaging/systemd) and AUR unit (kite-collector-aur) drifted — update both")
}

// unitDirectives strips comments and blank lines and normalizes the
// systemd continuation backslashes, leaving only behavior-bearing lines.
func unitDirectives(unit string) []string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
