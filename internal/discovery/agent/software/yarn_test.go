// yarn_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseYarnJSON_ValidInput(t *testing.T) {
	raw := "{\"type\":\"info\",\"data\":\"typescript@5.5.0\"}\n{\"type\":\"info\",\"data\":\"eslint@8.56.0\"}\n"
	result := ParseYarnJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "typescript", result.Items[0].SoftwareName)
	assert.Equal(t, "5.5.0", result.Items[0].Version)
	assert.Equal(t, "yarn", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "node.js")
	assert.False(t, result.HasErrors())
}

func TestParseYarnJSON_EmptyInput(t *testing.T) {
	result := ParseYarnJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseYarnJSON_ScopedPackage(t *testing.T) {
	raw := "{\"type\":\"info\",\"data\":\"@babel/core@7.24.0\"}\n"
	result := ParseYarnJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "@babel/core", result.Items[0].SoftwareName)
	assert.Equal(t, "7.24.0", result.Items[0].Version)
}

func TestParseYarnJSON_SkipsNonInfo(t *testing.T) {
	raw := "{\"type\":\"warning\",\"data\":\"some warning\"}\n{\"type\":\"info\",\"data\":\"pkg@1.0\"}\n"
	result := ParseYarnJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "pkg", result.Items[0].SoftwareName)
}

func TestParseYarnJSON_InvalidJSON(t *testing.T) {
	result := ParseYarnJSON("{bad\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "yarn", result.Errs[0].Collector)
}

// TestParseYarnJSON_SkipsObjectShapedData pins the fix for yarn emitting
// progressStart/progressTick events whose `data` field is an object rather
// than a "pkg@ver" string. The parser must treat those as benign skips,
// not parse errors.
func TestParseYarnJSON_SkipsObjectShapedData(t *testing.T) {
	raw := "" +
		"{\"type\":\"progressStart\",\"data\":{\"id\":0,\"total\":0}}\n" +
		"{\"type\":\"progressTick\",\"data\":{\"id\":0,\"current\":1}}\n" +
		"{\"type\":\"progressFinish\",\"data\":{\"id\":0}}\n" +
		"{\"type\":\"info\",\"data\":\"react@18.0.0\"}\n"

	result := ParseYarnJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "react", result.Items[0].SoftwareName)
	assert.Equal(t, "18.0.0", result.Items[0].Version)
	assert.False(t, result.HasErrors(),
		"object-shaped data must not be flagged as a parse error")
}

// TestParseYarnJSON_SkipsInfoWithObjectData covers the rare case where an
// info record itself carries an object payload (some yarn versions). It
// should be silently skipped, not flagged.
func TestParseYarnJSON_SkipsInfoWithObjectData(t *testing.T) {
	raw := "{\"type\":\"info\",\"data\":{\"name\":\"react\"}}\n"
	result := ParseYarnJSON(raw)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseYarnJSON_CPEHasTargetSW(t *testing.T) {
	raw := "{\"type\":\"info\",\"data\":\"typescript@5.5.0\"}\n"
	result := ParseYarnJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:typescript:5.5.0:*:*:*:*:node.js:*:*", result.Items[0].CPE23)
}
