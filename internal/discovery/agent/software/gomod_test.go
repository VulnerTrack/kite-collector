// gomod_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoModJSON_ValidInput(t *testing.T) {
	raw := "{\"Path\":\"github.com/example/myproject\",\"Main\":true}\n{\"Path\":\"golang.org/x/crypto\",\"Version\":\"v0.24.0\"}\n{\"Path\":\"github.com/google/uuid\",\"Version\":\"v1.6.0\"}\n"
	result := ParseGoModJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "crypto", result.Items[0].SoftwareName)
	assert.Equal(t, "x", result.Items[0].Vendor)
	assert.Equal(t, "0.24.0", result.Items[0].Version)
	assert.Equal(t, "gomod", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "go")
	assert.False(t, result.HasErrors())
}

func TestParseGoModJSON_EmptyInput(t *testing.T) {
	result := ParseGoModJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseGoModJSON_MainModuleOnly(t *testing.T) {
	raw := "{\"Path\":\"github.com/example/proj\",\"Main\":true}\n"
	result := ParseGoModJSON(raw)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseGoModJSON_InvalidJSON(t *testing.T) {
	result := ParseGoModJSON("{bad json")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "gomod", result.Errs[0].Collector)
}

func TestParseGoModJSON_CPEHasTargetSW(t *testing.T) {
	raw := "{\"Path\":\"github.com/google/uuid\",\"Version\":\"v1.6.0\"}\n"
	result := ParseGoModJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:google:uuid:1.6.0:*:*:*:*:go:*:*", result.Items[0].CPE23)
}
