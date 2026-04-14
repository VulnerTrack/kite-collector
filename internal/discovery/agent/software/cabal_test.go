// cabal_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCabalOutput_ValidInput(t *testing.T) {
	raw := "base-4.19.0.0 binary-0.8.9.1 text-2.1"
	result := ParseCabalOutput(raw)

	require.Len(t, result.Items, 3)
	assert.Equal(t, "base", result.Items[0].SoftwareName)
	assert.Equal(t, "4.19.0.0", result.Items[0].Version)
	assert.Equal(t, "cabal", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "haskell")
	assert.False(t, result.HasErrors())
}

func TestParseCabalOutput_EmptyInput(t *testing.T) {
	result := ParseCabalOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCabalOutput_NoVersion(t *testing.T) {
	result := ParseCabalOutput("nohyphendigit")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "cabal", result.Errs[0].Collector)
}

func TestParseCabalOutput_CPEHasTargetSW(t *testing.T) {
	raw := "text-2.1"
	result := ParseCabalOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:text:2.1:*:*:*:*:haskell:*:*", result.Items[0].CPE23)
}
