package ubuntumatrix

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// pkg builds a discovered row whose CPE is generated exactly the way the
// collector generates it, so a test fixture cannot accidentally encode a
// malformed CPE and mask a real check.
func pkg(name, version, arch string) Package {
	return Package{
		SoftwareName:   name,
		Version:        version,
		Architecture:   arch,
		PackageManager: "dpkg",
		CPE23:          software.BuildCPE23WithArch("", name, version, arch),
	}
}

// mangledPkg fabricates the pre-fix collector output for an epoch package:
// normalizeComponent used to delete the colon instead of splitting the epoch
// off, fusing the epoch digit into the CPE version (2:9.0.2114 → 29.0.2114).
// The checks must keep flagging that shape if it ever comes back.
func mangledPkg(name, version, arch string) Package {
	p := pkg(name, version, arch)
	p.CPE23 = software.BuildCPE23WithArch("", name, strings.Replace(version, ":", "", 1), arch)
	return p
}

func TestParseScanOutput(t *testing.T) {
	raw := []byte(`[
	  {"hostname":"box","software":[
	    {"software_name":"vim","version":"2:9.0.2114-1","architecture":"amd64",
	     "package_manager":"dpkg","cpe23":"cpe:2.3:a:*:vim:29.0.2114-1:*:*:*:*:*:amd64:*"}
	  ]},
	  {"hostname":"other","software":[
	    {"software_name":"libc6","version":"2.35-0ubuntu3","architecture":"i386",
	     "package_manager":"dpkg","cpe23":"cpe:2.3:a:*:libc6:2.35-0ubuntu3:*:*:*:*:*:i386:*"}
	  ]}
	]`)

	pkgs, err := ParseScanOutput(raw)
	require.NoError(t, err)
	require.Len(t, pkgs, 2)
	require.Equal(t, "vim", pkgs[0].SoftwareName)
	require.Equal(t, "i386", pkgs[1].Architecture)
	require.Equal(t, "libc6|i386", pkgs[1].Key())
}

func TestParseScanOutputToleratesMachinesWithoutSoftware(t *testing.T) {
	pkgs, err := ParseScanOutput([]byte(`[{"hostname":"box"}]`))
	require.NoError(t, err)
	require.Empty(t, pkgs)
}

// An empty stdout means the scan never produced its JSON document. Returning
// an error rather than an empty slice keeps that from being read as "this
// machine genuinely has no packages", which would pass a count check that
// only looks for a minimum.
func TestParseScanOutputRejectsEmptyStdout(t *testing.T) {
	_, err := ParseScanOutput([]byte("   \n"))
	require.ErrorContains(t, err, "no stdout")
}

func TestParseScanOutputRejectsGarbage(t *testing.T) {
	_, err := ParseScanOutput([]byte("not json"))
	require.ErrorContains(t, err, "decode scan output")
}

func TestCountParseErrors(t *testing.T) {
	stderr := strings.Join([]string{
		`{"time":"2026-07-24T00:00:00Z","level":"WARN","msg":"engine: software parse error","collector":"dpkg","line":7}`,
		`scan complete: 1 machine, 120 software (1 errors)`,
		`{"time":"2026-07-24T00:00:01Z","level":"INFO","msg":"engine: scan complete"}`,
		`{"time":"2026-07-24T00:00:02Z","level":"WARN","msg":"engine: software parse error","collector":"dpkg","line":9}`,
		`{ this is not valid json`,
	}, "\n")

	require.Equal(t, 2, CountParseErrors([]byte(stderr)))
}

func TestCountParseErrorsOnEmptyInput(t *testing.T) {
	require.Equal(t, 0, CountParseErrors(nil))
}

func TestFilterByPackageManager(t *testing.T) {
	pkgs := []Package{
		pkg("vim", "2:9.0", "amd64"),
		{SoftwareName: "requests", Version: "2.31.0", PackageManager: "pip"},
	}
	require.Len(t, FilterByPackageManager(pkgs, "dpkg"), 1)
	require.Len(t, FilterByPackageManager(pkgs, "pip"), 1)
	require.Empty(t, FilterByPackageManager(pkgs, "apt"))
}

// Multi-arch is the shape that matters here: one name, several rows.
func TestIndexByNameGroupsMultiArchRows(t *testing.T) {
	idx := IndexByName([]Package{
		pkg("libc6", "2.35-0ubuntu3", "amd64"),
		pkg("libc6", "2.35-0ubuntu3", "i386"),
		pkg("dpkg", "1.21.1ubuntu2", "amd64"),
	})
	require.Len(t, idx["libc6"], 2)
	require.Len(t, idx["dpkg"], 1)
}
