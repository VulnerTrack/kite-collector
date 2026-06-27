package loginventory

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogIsUpToDate is the staleness guard. It re-runs the
// generator against the live source tree and compares the output to
// the committed docs/LOG_CODES.md file. A contributor who adds or
// renames a LogCode constant but forgets to regenerate the catalog
// gets a failing test with the exact regeneration command in the
// error message — no production code ships with a stale catalog.
func TestCatalogIsUpToDate(t *testing.T) {
	root, err := findRepoRoot()
	require.NoError(t, err, "must locate repo root (go.mod)")

	want, err := Generate(root)
	require.NoError(t, err)

	committed, err := os.ReadFile(filepath.Join(root, "docs", "LOG_CODES.md"))
	require.NoError(t, err, "docs/LOG_CODES.md must exist — regenerate with: go run ./tools/loginventory > docs/LOG_CODES.md")

	if !bytes.Equal(want, committed) {
		t.Fatalf(
			"docs/LOG_CODES.md is out of date relative to the live logcodes.go files.\n"+
				"Regenerate with:\n\n  go run ./tools/loginventory > docs/LOG_CODES.md\n\n"+
				"Diff summary: committed=%d bytes, generated=%d bytes",
			len(committed), len(want))
	}
}

// TestGenerate_FindsEveryShippedPackage smoke-tests the discovery
// half of the generator independently of the rendered output, so a
// future change that breaks file-walking surfaces with a clear error
// instead of a confusing diff.
func TestGenerate_FindsEveryShippedPackage(t *testing.T) {
	root, err := findRepoRoot()
	require.NoError(t, err)

	body, err := Generate(root)
	require.NoError(t, err)

	// At minimum the 9 packages shipped through iter 6 must be in the
	// catalog. New packages added later will only INCREASE this set.
	wantPackages := []string{
		"`rest`",
		"`main`", // cmd/kite-collector — package is "main"
		"`dashboard`",
		"`dedup`",
		"`engine`",
		"`enrollment`",
		"`safety`",
		"`scan`",
		"`sqlite`", // internal/store/sqlite — package is "sqlite", namespace prefix is "sqlitestore"
	}
	bodyStr := string(body)
	for _, p := range wantPackages {
		assert.Contains(t, bodyStr, p,
			"catalog must include the %s package section", p)
	}
}

// TestGenerate_DiscoversAllLogcodesFiles asserts the file walker
// finds every shipped logcodes.go. If a future contributor adds a
// new instrumented package, they get an automatic discovery — no
// manual list maintenance.
func TestGenerate_DiscoversAllLogcodesFiles(t *testing.T) {
	root, err := findRepoRoot()
	require.NoError(t, err)

	files, err := findLogcodesFiles(root)
	require.NoError(t, err)

	// Each shipped file must show up; the count must match a minimum
	// floor so a future contributor noticing the count diverged knows
	// to investigate before bumping the floor.
	minFiles := 9
	assert.GreaterOrEqual(t, len(files), minFiles,
		"expected at least %d logcodes.go files; got %d. If you added a new package, increment minFiles in this test.",
		minFiles, len(files))

	// vendor/ and tools/ must never appear in the catalog scope.
	for _, f := range files {
		assert.NotContains(t, f, "/vendor/", "vendor tree must be skipped")
		assert.NotContains(t, f, "/tools/", "tools tree must be skipped — those files describe the generator, not shipped code")
	}
}

// findRepoRoot replicates the cmd's repo-root walk so the test can
// run from anywhere inside the module.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	d := cwd
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", &noRepoError{cwd: cwd}
		}
		d = parent
	}
}

type noRepoError struct{ cwd string }

func (e *noRepoError) Error() string {
	return "go.mod not found at or above " + e.cwd + " (run test from inside the kite-collector module)"
}

// Avoid an unused-import compile failure when the standard-library
// `strings` import drifts out — keeps the file robust to future test
// additions that import strings inline.
var _ = strings.Contains
