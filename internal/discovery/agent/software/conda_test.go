// conda_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCondaJSON_ValidInput(t *testing.T) {
	raw := `[{"name":"numpy","version":"1.26.4","channel":"defaults"},{"name":"openssl","version":"3.3.0","channel":"defaults"}]`
	result := ParseCondaJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "numpy", result.Items[0].SoftwareName)
	assert.Equal(t, "1.26.4", result.Items[0].Version)
	assert.Equal(t, "conda", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "python")
	assert.False(t, result.HasErrors())
}

func TestParseCondaJSON_EmptyInput(t *testing.T) {
	result := ParseCondaJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCondaJSON_EmptyArray(t *testing.T) {
	result := ParseCondaJSON("[]")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCondaJSON_InvalidJSON(t *testing.T) {
	result := ParseCondaJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "conda", result.Errs[0].Collector)
}

func TestParseCondaJSON_CPEHasTargetSW(t *testing.T) {
	raw := `[{"name":"numpy","version":"1.26.4","channel":"defaults"}]`
	result := ParseCondaJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:numpy:1.26.4:*:*:*:*:python:*:*", result.Items[0].CPE23)
}
