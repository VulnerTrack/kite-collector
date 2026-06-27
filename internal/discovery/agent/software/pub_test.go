// pub_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePubJSON_ValidInput(t *testing.T) {
	raw := `{"packages":[{"name":"http","version":"1.2.1"},{"name":"path","version":"1.9.0"}]}`
	result := ParsePubJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "http", result.Items[0].SoftwareName)
	assert.Equal(t, "1.2.1", result.Items[0].Version)
	assert.Equal(t, "pub", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "dart")
	assert.False(t, result.HasErrors())
}

func TestParsePubJSON_EmptyInput(t *testing.T) {
	result := ParsePubJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePubJSON_EmptyPackages(t *testing.T) {
	result := ParsePubJSON(`{"packages":[]}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePubJSON_InvalidJSON(t *testing.T) {
	result := ParsePubJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pub", result.Errs[0].Collector)
}

func TestParsePubJSON_CPEHasTargetSW(t *testing.T) {
	raw := `{"packages":[{"name":"http","version":"1.2.1"}]}`
	result := ParsePubJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:http:1.2.1:*:*:*:*:dart:*:*", result.Items[0].CPE23)
}
