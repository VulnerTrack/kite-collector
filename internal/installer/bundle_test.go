package installer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testUpstreamSHA = "9c06dd0b8fbe76129cff5bebc79277044213d5cddccb9ddfe2179606908a817e"
	testPayloadSHA  = "bb20b589037665aab60060d313a10d2d2c0b2e5955e7fba52a2dc88b445eb8cd"
)

func validManifest() BundleManifest {
	return BundleManifest{
		SchemaVersion:    1,
		NaturalKey:       "bundled:osqueryd:5.15.0:self_contained_exe",
		ComponentName:    "osqueryd",
		ComponentVersion: "5.15.0",
		UpstreamSHA256:   testUpstreamSHA,
		VendoredSHA256:   testUpstreamSHA,
		SourceURL:        "https://example.invalid/osquery-5.15.0.msi",
		LicenseID:        "Apache-2.0",
		CPE23:            "cpe:2.3:a:osquery:osquery:5.15.0:*:*:*:*:*:*:*",
		ArtifactFormat:   "self_contained_exe",
		Files: []BundleFile{
			{Path: bundleDaemonPath, SHA256: testPayloadSHA, Size: 42},
		},
	}
}

func TestBundleManifest_ValidAcceptsPin(t *testing.T) {
	require.NoError(t, validManifest().Validate())
}

// TestBundlePathsAreFSPaths guards the embed contract. These are io/fs paths,
// not host paths: a backslash here would resolve on nobody's machine, and the
// failure would only show up at install time on Windows — the one platform the
// artifact exists for.
func TestBundlePathsAreFSPaths(t *testing.T) {
	assert.Equal(t, "osquerypayload/payload", bundleRoot)
	assert.Equal(t, bundleRoot+"/manifest.json", bundleManifestPath)
	for _, p := range []string{bundleRoot, bundleManifestPath, bundleDaemonPath} {
		assert.NotContains(t, p, `\`, "embed paths use forward slashes")
		assert.False(t, strings.HasPrefix(p, "/"), "embed paths are relative")
	}
}

// TestBundleManifest_ChecksumIntegrityAxiom is the load-bearing assertion of
// RFC-0156 Section 4.2: vendored_sha256 must equal upstream_sha256 for every
// BundledDependency, always. A manifest that fails it must not produce an
// install — this is the in-artifact half of the same gate scripts/build-msi.sh
// and scripts/stage-osquery-embed.sh enforce at build time.
func TestBundleManifest_ChecksumIntegrityAxiom(t *testing.T) {
	m := validManifest()
	m.VendoredSHA256 = testPayloadSHA // a real digest, of the wrong artifact

	err := m.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum-integrity violation")
}

func TestBundleManifest_RejectsMalformed(t *testing.T) {
	cases := map[string]func(*BundleManifest){
		"no component name":    func(m *BundleManifest) { m.ComponentName = "" },
		"no component version": func(m *BundleManifest) { m.ComponentVersion = "" },
		"short upstream digest": func(m *BundleManifest) {
			m.UpstreamSHA256 = "deadbeef"
			m.VendoredSHA256 = "deadbeef"
		},
		"non-hex digest": func(m *BundleManifest) {
			bad := "zz" + testUpstreamSHA[2:]
			m.UpstreamSHA256 = bad
			m.VendoredSHA256 = bad
		},
		"no payload files": func(m *BundleManifest) { m.Files = nil },
		"payload entry without a path": func(m *BundleManifest) {
			m.Files = []BundleFile{{SHA256: testPayloadSHA}}
		},
		"payload entry without a digest": func(m *BundleManifest) {
			m.Files = []BundleFile{{Path: bundleDaemonPath}}
		},
		"daemon missing from the payload": func(m *BundleManifest) {
			m.Files = []BundleFile{
				{Path: "osquery/certs/certs.pem", SHA256: testPayloadSHA},
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mutate(&m)
			assert.Error(t, m.Validate())
		})
	}
}

func TestParseBundleManifest_RejectsInvalidJSON(t *testing.T) {
	_, err := parseBundleManifest([]byte("{not json"))
	assert.Error(t, err)
}

// TestParseBundleManifest_ValidatesEagerly guards the "no caller can hold an
// unvalidated manifest" property: decoding a well-formed JSON document that
// violates the axiom must still fail.
func TestParseBundleManifest_ValidatesEagerly(t *testing.T) {
	raw := []byte(`{
	  "component_name": "osqueryd",
	  "component_version": "5.15.0",
	  "upstream_sha256": "` + testUpstreamSHA + `",
	  "vendored_sha256": "` + testPayloadSHA + `",
	  "files": [{"path": "` + bundleDaemonPath + `", "sha256": "` + testPayloadSHA + `"}]
	}`)
	_, err := parseBundleManifest(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum-integrity violation")
}

func TestIsSHA256Hex(t *testing.T) {
	assert.True(t, isSHA256Hex(testUpstreamSHA))
	assert.False(t, isSHA256Hex(""))
	assert.False(t, isSHA256Hex(testUpstreamSHA[:63]))
	assert.False(t, isSHA256Hex(testUpstreamSHA+"a"))
	assert.False(t, isSHA256Hex("AB"+testUpstreamSHA[2:]),
		"uppercase must be normalised by the caller, not silently accepted")
	assert.False(t, isSHA256Hex("zz"+testUpstreamSHA[2:]))
}

// TestOsquerySvcConfig_MatchesDeployedContract pins the flags and the
// pipe/socket name RFC-0151's client already depends on. Drift here would be
// invisible in CI and fatal in the field: the collector would dial a pipe
// nothing is listening on and report the source as inert.
func TestOsquerySvcConfig_MatchesDeployedContract(t *testing.T) {
	opts := Options{BinaryDir: "/opt/kite", CertsDir: "/var/lib/kite"}
	cfg := BuildOsquerySvcConfig(opts)

	assert.Equal(t, OsquerySvcName, cfg.Name)
	assert.Equal(t, OsquerydPath(opts), cfg.Executable)
	assert.Contains(t, cfg.Arguments,
		"--extensions_socket="+OsqueryExtensionsEndpoint())
	assert.False(t, cfg.Option["UserService"].(bool),
		"the daemon needs LocalSystem; a per-user registration cannot work")

	for _, flag := range []string{"--flagfile=", "--config_path=", "--database_path=", "--logger_path="} {
		found := false
		for _, arg := range cfg.Arguments {
			if len(arg) >= len(flag) && arg[:len(flag)] == flag {
				found = true
				break
			}
		}
		assert.True(t, found, "service command line must carry %s", flag)
	}
}
