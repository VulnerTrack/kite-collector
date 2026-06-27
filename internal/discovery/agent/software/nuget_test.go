// nuget_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNuGetJSON_ValidInput(t *testing.T) {
	raw := `{"projects":[{"frameworks":[{"topLevelPackages":[{"id":"Newtonsoft.Json","resolvedVersion":"13.0.3"},{"id":"Serilog","resolvedVersion":"3.1.1"}]}]}]}`
	result := ParseNuGetJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "Newtonsoft.Json", result.Items[0].SoftwareName)
	assert.Equal(t, "13.0.3", result.Items[0].Version)
	assert.Equal(t, "nuget", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, ".net")
	assert.False(t, result.HasErrors())
}

func TestParseNuGetJSON_EmptyInput(t *testing.T) {
	result := ParseNuGetJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseNuGetJSON_NoProjects(t *testing.T) {
	result := ParseNuGetJSON(`{"projects":[]}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseNuGetJSON_InvalidJSON(t *testing.T) {
	result := ParseNuGetJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "nuget", result.Errs[0].Collector)
}

func TestParseNuGetJSON_DeduplicatesAcrossFrameworks(t *testing.T) {
	raw := `{"projects":[{"frameworks":[{"topLevelPackages":[{"id":"Pkg","resolvedVersion":"1.0"}]},{"topLevelPackages":[{"id":"Pkg","resolvedVersion":"1.0"}]}]}]}`
	result := ParseNuGetJSON(raw)

	require.Len(t, result.Items, 1)
}

func TestParseNuGetJSON_CPEHasTargetSW(t *testing.T) {
	raw := `{"projects":[{"frameworks":[{"topLevelPackages":[{"id":"Newtonsoft.Json","resolvedVersion":"13.0.3"}]}]}]}`
	result := ParseNuGetJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:newtonsoft.json:13.0.3:*:*:*:*:.net:*:*", result.Items[0].CPE23)
}
