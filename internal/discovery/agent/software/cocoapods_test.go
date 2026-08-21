// cocoapods_test.go
package software

import (
	"context"
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

// Reproduces the field failure "pod list: wait pod: exit status 1"
// seen when the agent runs under sudo: CocoaPods hard-refuses to run
// as root, printing "[!] You cannot run CocoaPods as root." wrapped in
// ANSI color escapes. That is an environment condition, not a
// collector failure — Collect must return a benign empty inventory.
func TestCocoaPodsCollect_RootRefusalIsBenign(t *testing.T) {
	fakeToolOnPath(t, "pod", `printf '\033[31m[!] You cannot run CocoaPods as root.\033[39m\n'
exit 1
`)

	res, err := NewCocoaPods().Collect(context.Background())
	require.NoError(t, err, "pod's refusal to run as root must not surface as a collector failure")
	assert.Empty(t, res.Items)
	assert.Empty(t, res.Errs)
}

// Any other non-zero pod exit is a genuine failure and must surface
// with pod's stderr folded in.
func TestCocoaPodsCollect_OtherFailureSurfacesStderr(t *testing.T) {
	fakeToolOnPath(t, "pod", `echo "Unable to load a specification" >&2
exit 1
`)

	_, err := NewCocoaPods().Collect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Unable to load a specification")
}

// pod/CLAide colorises entry lines when it believes it has a TTY; the
// parser must read through the escapes instead of parsing zero pods.
func TestParseCocoaPodsOutput_StripsANSIEscapes(t *testing.T) {
	raw := "\x1b[32m-> Alamofire (5.9.1)\x1b[39m\n\x1b[32m-> SwiftyJSON (5.0.2)\x1b[39m\n"
	result := ParseCocoaPodsOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "Alamofire", result.Items[0].SoftwareName)
	assert.Equal(t, "5.9.1", result.Items[0].Version)
	assert.False(t, result.HasErrors())
}
