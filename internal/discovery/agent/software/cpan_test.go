// cpan_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCPANOutput_ValidInput(t *testing.T) {
	raw := "JSON::XS\t4.03\nMoose\t2.2207\n"
	result := ParseCPANOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "JSON::XS", result.Items[0].SoftwareName)
	assert.Equal(t, "4.03", result.Items[0].Version)
	assert.Equal(t, "cpan", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "perl")
	assert.False(t, result.HasErrors())
}

func TestParseCPANOutput_EmptyInput(t *testing.T) {
	result := ParseCPANOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCPANOutput_UndefVersion(t *testing.T) {
	raw := "Some::Module\tundef\n"
	result := ParseCPANOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "", result.Items[0].Version)
}

func TestParseCPANOutput_MalformedLine(t *testing.T) {
	result := ParseCPANOutput("notabseparated\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "cpan", result.Errs[0].Collector)
}

func TestParseCPANOutput_CPEHasTargetSW(t *testing.T) {
	raw := "JSON::XS\t4.03\n"
	result := ParseCPANOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Contains(t, result.Items[0].CPE23, "perl")
}
