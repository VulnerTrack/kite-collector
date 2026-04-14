// hex_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHexOutput_ValidInput(t *testing.T) {
	raw := "* jason 1.4.1 (Hex package) (mix)\n  locked at 1.4.1\n* plug 1.15.3 (Hex package) (mix)\n  locked at 1.15.3\n"
	result := ParseHexOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "jason", result.Items[0].SoftwareName)
	assert.Equal(t, "1.4.1", result.Items[0].Version)
	assert.Equal(t, "hex", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "elixir")
	assert.False(t, result.HasErrors())
}

func TestParseHexOutput_EmptyInput(t *testing.T) {
	result := ParseHexOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseHexOutput_SkipsNonDepLines(t *testing.T) {
	raw := "Dependencies loaded\n* phoenix 1.7.12 (Hex package)\n"
	result := ParseHexOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "phoenix", result.Items[0].SoftwareName)
}

func TestParseHexOutput_CPEHasTargetSW(t *testing.T) {
	raw := "* phoenix 1.7.12 (Hex package)\n"
	result := ParseHexOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:phoenix:1.7.12:*:*:*:*:elixir:*:*", result.Items[0].CPE23)
}
