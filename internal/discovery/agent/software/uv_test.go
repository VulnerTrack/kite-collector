package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUvToolList(t *testing.T) {
	// Real `uv tool list` shape: a tool line followed by its entrypoints.
	raw := `bandit v1.9.4
- bandit
- bandit-baseline
- bandit-config-generator
git-filter-repo v2.47.0
- git-filter-repo
mypy v1.19.1
- dmypy
- mypy
ruff v0.15.7
- ruff
`
	res := ParseUvToolList(raw)
	require.Empty(t, res.Errs)
	require.Len(t, res.Items, 4, "one row per tool, entrypoint lines skipped")

	got := map[string]string{}
	for _, it := range res.Items {
		assert.Equal(t, "uv", it.PackageManager)
		assert.NotEmpty(t, it.CPE23)
		got[it.SoftwareName] = it.Version
	}
	assert.Equal(t, "1.9.4", got["bandit"], "leading 'v' stripped from version")
	assert.Equal(t, "2.47.0", got["git-filter-repo"])
	assert.Equal(t, "1.19.1", got["mypy"])
	assert.Equal(t, "0.15.7", got["ruff"])
}

func TestParseUvToolList_Empty(t *testing.T) {
	// uv prints a status line when nothing is installed — not a tool.
	res := ParseUvToolList("No tools installed.\n")
	assert.Empty(t, res.Items)
	assert.Empty(t, res.Errs)

	assert.Empty(t, ParseUvToolList("").Items)
}

func TestUv_Name(t *testing.T) {
	assert.Equal(t, "uv", NewUv().Name())
}

func TestIsUvVersion(t *testing.T) {
	assert.True(t, isUvVersion("v1.9.4"))
	assert.True(t, isUvVersion("v0.15.7"))
	assert.False(t, isUvVersion("tools"), "a word, not a version")
	assert.False(t, isUvVersion("version"))
	assert.False(t, isUvVersion("v"))
	assert.False(t, isUvVersion(""))
}
