// composer_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComposerJSON_ValidInput(t *testing.T) {
	raw := `{"installed":[{"name":"laravel/framework","version":"v11.0.0"},{"name":"monolog/monolog","version":"3.5.0"}]}`
	result := ParseComposerJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "framework", result.Items[0].SoftwareName)
	assert.Equal(t, "laravel", result.Items[0].Vendor)
	assert.Equal(t, "11.0.0", result.Items[0].Version)
	assert.Equal(t, "composer", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "php")
	assert.False(t, result.HasErrors())
}

func TestParseComposerJSON_EmptyInput(t *testing.T) {
	result := ParseComposerJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseComposerJSON_EmptyInstalled(t *testing.T) {
	result := ParseComposerJSON(`{"installed":[]}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseComposerJSON_InvalidJSON(t *testing.T) {
	result := ParseComposerJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "composer", result.Errs[0].Collector)
}

func TestParseComposerJSON_CPEHasTargetSW(t *testing.T) {
	raw := `{"installed":[{"name":"monolog/monolog","version":"3.5.0"}]}`
	result := ParseComposerJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:monolog:monolog:3.5.0:*:*:*:*:php:*:*", result.Items[0].CPE23)
}
