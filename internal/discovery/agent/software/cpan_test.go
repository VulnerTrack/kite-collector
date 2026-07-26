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

// A line that is not a "<module>\t<version>" record is cpan(1) diagnostic
// chatter, not corrupt data — it must be skipped silently, never reported as
// a parse error.
func TestParseCPANOutput_SkipsNonRecordLine(t *testing.T) {
	result := ParseCPANOutput("notabseparated\n")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

// Regression for the observed WARN "software-inventory parse error /
// collector=cpan": cpan writes its logger banner to stdout among the module
// list. Real records must still be parsed, and the banner must not surface as
// an error.
func TestParseCPANOutput_SkipsLoggerBanner(t *testing.T) {
	raw := "Loading internal logger. Log::Log4perl recommended for better logging\n" +
		"JSON::XS\t4.03\n" +
		"Moose\t2.2207\n"
	result := ParseCPANOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "JSON::XS", result.Items[0].SoftwareName)
	assert.Equal(t, "Moose", result.Items[1].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParseCPANOutput_CPEHasTargetSW(t *testing.T) {
	raw := "JSON::XS\t4.03\n"
	result := ParseCPANOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Contains(t, result.Items[0].CPE23, "perl")
}
