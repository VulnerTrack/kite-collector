// cran_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCRANOutput_ValidInput(t *testing.T) {
	raw := "\"\",\"Package\",\"Version\"\n\"1\",\"base\",\"4.3.1\"\n\"2\",\"ggplot2\",\"3.5.0\"\n"
	result := ParseCRANOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "base", result.Items[0].SoftwareName)
	assert.Equal(t, "4.3.1", result.Items[0].Version)
	assert.Equal(t, "cran", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "r")
	assert.False(t, result.HasErrors())
}

func TestParseCRANOutput_EmptyInput(t *testing.T) {
	result := ParseCRANOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCRANOutput_HeaderOnly(t *testing.T) {
	raw := "\"\",\"Package\",\"Version\"\n"
	result := ParseCRANOutput(raw)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCRANOutput_CPEHasTargetSW(t *testing.T) {
	raw := "\"\",\"Package\",\"Version\"\n\"1\",\"ggplot2\",\"3.5.0\"\n"
	result := ParseCRANOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:ggplot2:3.5.0:*:*:*:*:r:*:*", result.Items[0].CPE23)
}
