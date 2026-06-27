// juliapkg_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJuliaPkgOutput_ValidInput(t *testing.T) {
	raw := "HTTP 1.10.1\nJSON 0.21.4\n"
	result := ParseJuliaPkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "HTTP", result.Items[0].SoftwareName)
	assert.Equal(t, "1.10.1", result.Items[0].Version)
	assert.Equal(t, "juliapkg", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "julia")
	assert.False(t, result.HasErrors())
}

func TestParseJuliaPkgOutput_EmptyInput(t *testing.T) {
	result := ParseJuliaPkgOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseJuliaPkgOutput_MalformedLine(t *testing.T) {
	result := ParseJuliaPkgOutput("nospace\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "juliapkg", result.Errs[0].Collector)
}

func TestParseJuliaPkgOutput_CPEHasTargetSW(t *testing.T) {
	raw := "HTTP 1.10.1\n"
	result := ParseJuliaPkgOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:http:1.10.1:*:*:*:*:julia:*:*", result.Items[0].CPE23)
}
