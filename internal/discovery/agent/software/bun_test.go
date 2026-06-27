// bun_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBunOutput_ValidInput(t *testing.T) {
	raw := "/home/user/.bun/install/global\n├── typescript@5.5.0\n└── eslint@8.56.0\n"
	result := ParseBunOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "typescript", result.Items[0].SoftwareName)
	assert.Equal(t, "5.5.0", result.Items[0].Version)
	assert.Equal(t, "bun", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "node.js")
	assert.False(t, result.HasErrors())
}

func TestParseBunOutput_EmptyInput(t *testing.T) {
	result := ParseBunOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseBunOutput_ScopedPackage(t *testing.T) {
	raw := "├── @babel/core@7.24.0\n"
	result := ParseBunOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "@babel/core", result.Items[0].SoftwareName)
	assert.Equal(t, "7.24.0", result.Items[0].Version)
}

func TestParseBunOutput_CPEHasTargetSW(t *testing.T) {
	raw := "├── typescript@5.5.0\n"
	result := ParseBunOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:typescript:5.5.0:*:*:*:*:node.js:*:*", result.Items[0].CPE23)
}
