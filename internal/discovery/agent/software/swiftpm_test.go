// swiftpm_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSwiftPMJSON_ValidInput(t *testing.T) {
	raw := `{"dependencies":[{"identity":"alamofire","version":"5.9.1","dependencies":[]},{"identity":"swiftyjson","version":"5.0.2","dependencies":[]}]}`
	result := ParseSwiftPMJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "alamofire", result.Items[0].SoftwareName)
	assert.Equal(t, "5.9.1", result.Items[0].Version)
	assert.Equal(t, "swiftpm", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "ios")
	assert.False(t, result.HasErrors())
}

func TestParseSwiftPMJSON_EmptyInput(t *testing.T) {
	result := ParseSwiftPMJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseSwiftPMJSON_NestedDeps(t *testing.T) {
	raw := `{"dependencies":[{"identity":"parent","version":"1.0","dependencies":[{"identity":"child","version":"2.0","dependencies":[]}]}]}`
	result := ParseSwiftPMJSON(raw)

	require.Len(t, result.Items, 2)
	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "parent")
	assert.Contains(t, names, "child")
}

func TestParseSwiftPMJSON_InvalidJSON(t *testing.T) {
	result := ParseSwiftPMJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "swiftpm", result.Errs[0].Collector)
}

func TestParseSwiftPMJSON_CPEHasTargetSW(t *testing.T) {
	raw := `{"dependencies":[{"identity":"alamofire","version":"5.9.1","dependencies":[]}]}`
	result := ParseSwiftPMJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:alamofire:5.9.1:*:*:*:*:ios:*:*", result.Items[0].CPE23)
}
