package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseDpkgOutput
// ---------------------------------------------------------------------------

func TestParseDpkgOutput_ValidLines(t *testing.T) {
	raw := "curl\t7.88.1-10+deb12u5\nwget\t1.21.3-1\n"
	result := ParseDpkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "7.88.1-10+deb12u5", result.Items[0].Version)
	assert.Equal(t, "dpkg", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)
	assert.Equal(t, "wget", result.Items[1].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParseDpkgOutput_EmptyInput(t *testing.T) {
	result := ParseDpkgOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseDpkgOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "no-tab-here\n"
	result := ParseDpkgOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "dpkg", result.Errs[0].Collector)
	assert.Equal(t, 1, result.Errs[0].Line)
	assert.Equal(t, "no-tab-here", result.Errs[0].RawLine)
}

func TestParseDpkgOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "good\t1.0\nbadline\ngood2\t2.0\n"
	result := ParseDpkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "good", result.Items[0].SoftwareName)
	assert.Equal(t, "good2", result.Items[1].SoftwareName)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, 2, result.Errs[0].Line)
}

func TestParseDpkgOutput_EmptyPackageName_Skipped(t *testing.T) {
	raw := "\t1.0\n"
	result := ParseDpkgOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
}

func TestParseDpkgOutput_SkipsBlankLines(t *testing.T) {
	raw := "vim\t9.0\n\nnano\t7.2\n"
	result := ParseDpkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.False(t, result.HasErrors())
}

// ---------------------------------------------------------------------------
// ParsePacmanOutput
// ---------------------------------------------------------------------------

func TestParsePacmanOutput_ValidLines(t *testing.T) {
	raw := "linux 6.19.9.zen1-1\nbash 5.2.026-2\n"
	result := ParsePacmanOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "linux", result.Items[0].SoftwareName)
	assert.Equal(t, "6.19.9.zen1-1", result.Items[0].Version)
	assert.Equal(t, "pacman", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)
	assert.False(t, result.HasErrors())
}

func TestParsePacmanOutput_EmptyInput(t *testing.T) {
	result := ParsePacmanOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePacmanOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "noversion\n"
	result := ParsePacmanOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pacman", result.Errs[0].Collector)
	assert.Equal(t, 1, result.Errs[0].Line)
}

func TestParsePacmanOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "vim 9.1.0-1\nbad\ngit 2.47.0-1\n"
	result := ParsePacmanOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "vim", result.Items[0].SoftwareName)
	assert.Equal(t, "git", result.Items[1].SoftwareName)
}

func TestParsePacmanOutput_PackageWithHyphen(t *testing.T) {
	raw := "lib32-glibc 2.39-1\n"
	result := ParsePacmanOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "lib32-glibc", result.Items[0].SoftwareName)
	assert.Equal(t, "2.39-1", result.Items[0].Version)
}

// ---------------------------------------------------------------------------
// ParseRPMOutput
// ---------------------------------------------------------------------------

func TestParseRPMOutput_ValidLines(t *testing.T) {
	raw := "bash\t5.2.26-1.fc39\tFedora Project\n"
	result := ParseRPMOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "bash", result.Items[0].SoftwareName)
	assert.Equal(t, "5.2.26-1.fc39", result.Items[0].Version)
	assert.Equal(t, "Fedora Project", result.Items[0].Vendor)
	assert.Equal(t, "rpm", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseRPMOutput_EmptyInput(t *testing.T) {
	result := ParseRPMOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseRPMOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "notabs\n"
	result := ParseRPMOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "rpm", result.Errs[0].Collector)
}

func TestParseRPMOutput_VendorNone_TreatedAsEmpty(t *testing.T) {
	raw := "zlib\t1.2.13-1.fc39\t(none)\n"
	result := ParseRPMOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "", result.Items[0].Vendor)
}

func TestParseRPMOutput_ThreeFields_ExtractsVendor(t *testing.T) {
	raw := "openssl\t3.1.4-2.el9\tRed Hat, Inc.\n"
	result := ParseRPMOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "Red Hat, Inc.", result.Items[0].Vendor)
	assert.Contains(t, result.Items[0].CPE23, "red_hat_inc.")
}

func TestParseRPMOutput_TwoFields_NoVendor(t *testing.T) {
	raw := "glibc\t2.38-6.fc39\n"
	result := ParseRPMOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "glibc", result.Items[0].SoftwareName)
	assert.Equal(t, "", result.Items[0].Vendor)
}

func TestParseRPMOutput_EmptyPackageName_Skipped(t *testing.T) {
	raw := "\t1.0\tvendor\n"
	result := ParseRPMOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
}
