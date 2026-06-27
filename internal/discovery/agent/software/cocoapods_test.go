// cocoapods_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCocoaPodsOutput_ValidInput(t *testing.T) {
	raw := "-> Alamofire (5.9.1)\n   Elegant HTTP Networking in Swift\n-> SwiftyJSON (5.0.2)\n   Better JSON handling\n"
	result := ParseCocoaPodsOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "Alamofire", result.Items[0].SoftwareName)
	assert.Equal(t, "5.9.1", result.Items[0].Version)
	assert.Equal(t, "cocoapods", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "ios")
	assert.False(t, result.HasErrors())
}

func TestParseCocoaPodsOutput_EmptyInput(t *testing.T) {
	result := ParseCocoaPodsOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCocoaPodsOutput_DashPrefix(t *testing.T) {
	raw := "- AFNetworking (4.0.1)\n"
	result := ParseCocoaPodsOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "AFNetworking", result.Items[0].SoftwareName)
	assert.Equal(t, "4.0.1", result.Items[0].Version)
}

func TestParseCocoaPodsOutput_MissingVersion(t *testing.T) {
	raw := "-> BadPod noparens\n"
	result := ParseCocoaPodsOutput(raw)
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "cocoapods", result.Errs[0].Collector)
}

func TestParseCocoaPodsOutput_CPEHasTargetSW(t *testing.T) {
	raw := "-> Alamofire (5.9.1)\n"
	result := ParseCocoaPodsOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:alamofire:5.9.1:*:*:*:*:ios:*:*", result.Items[0].CPE23)
}
