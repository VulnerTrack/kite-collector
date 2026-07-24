package ubuntumatrix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testDigest(seed string) string {
	return "sha256:" + strings.Repeat(seed, 64)[:64]
}

func lts(slug, version string) Target {
	return Target{
		Slug:          slug,
		DistroFamily:  "ubuntu",
		Version:       version,
		Architecture:  "amd64",
		IsLTS:         true,
		SupportStatus: SupportActive,
		BaseImageRef:  "docker.io/library/ubuntu:" + version,
		SeedScript:    "fixtures/x.seed.sh",
		ExpectedFile:  "fixtures/expected/x.expected.json",
	}
}

// The shipped matrix must always load, so a malformed edit to targets.json
// fails in the fast unit suite rather than only when Docker is available.
func TestLoadMatrixShipped(t *testing.T) {
	m, err := LoadMatrix()
	require.NoError(t, err)
	require.Equal(t, []string{
		"ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-devel",
	}, m.Slugs())

	for _, target := range m.Targets {
		require.FileExists(t, Path(target.SeedScript), target.Slug)
		require.FileExists(t, Path(target.ExpectedFile), target.Slug)

		exp, err := LoadExpectation(target)
		require.NoError(t, err, target.Slug)
		require.Equal(t, "dpkg", exp.PackageManager, target.Slug)
	}
}

// R3 as a structural invariant: it must be impossible to promote a leg to
// blocking without first committing the digest it was reviewed against.
func TestShippedBlockingTargetsArePinned(t *testing.T) {
	m, err := LoadMatrix()
	require.NoError(t, err)
	for _, target := range m.Targets {
		require.NoErrorf(t, target.RequirePin(),
			"target %s is blocking without a pinned digest", target.Slug)
	}
}

func TestTargetPinnedRef(t *testing.T) {
	target := lts("ubuntu-22.04", "22.04")
	require.False(t, target.Pinned())
	require.Equal(t, "docker.io/library/ubuntu:22.04", target.PinnedRef())
	require.Equal(t, "22.04", target.Tag())
	require.Equal(t, "docker.io/library/ubuntu", target.Repository())

	target.ImageDigest = testDigest("a")
	require.True(t, target.Pinned())
	require.Equal(t, "docker.io/library/ubuntu@"+testDigest("a"), target.PinnedRef())
}

func TestTargetNaturalKey(t *testing.T) {
	require.Equal(t, "ubuntu|22.04|amd64", lts("ubuntu-22.04", "22.04").NaturalKey())
}

// §4.2.1 axiom: blocking=1 is only valid where is_lts=1 and status=active.
// An EOL or interim target must never silently become PR-blocking.
func TestTargetValidateRejectsBlockingNonSupported(t *testing.T) {
	target := lts("ubuntu-20.04", "20.04")
	target.SupportStatus = SupportLegacy
	target.Blocking = true
	require.ErrorContains(t, target.Validate(), "blocking requires")

	interim := lts("ubuntu-devel", "devel")
	interim.IsLTS = false
	interim.SupportStatus = SupportInterim
	interim.Blocking = true
	require.ErrorContains(t, interim.Validate(), "blocking requires")
}

func TestTargetValidateRejectsUnknownSupportStatus(t *testing.T) {
	target := lts("ubuntu-22.04", "22.04")
	target.SupportStatus = "supported-ish"
	require.ErrorContains(t, target.Validate(), "closed enum")
}

func TestTargetValidateRejectsMalformedDigest(t *testing.T) {
	target := lts("ubuntu-22.04", "22.04")
	target.ImageDigest = "sha256:not-a-digest"
	require.ErrorContains(t, target.Validate(), "sha256:")
}

func TestTargetRequirePin(t *testing.T) {
	target := lts("ubuntu-22.04", "22.04")
	require.NoError(t, target.RequirePin(), "informational legs may float")

	target.Blocking = true
	err := target.RequirePin()
	require.ErrorContains(t, err, "pin-ubuntu-matrix")

	target.ImageDigest = testDigest("b")
	require.NoError(t, target.RequirePin())
}

// R4: declared coverage is checked against the policy rather than being
// allowed to drift away from it silently.
func TestMatrixValidateEnforcesPolicyCoverage(t *testing.T) {
	m := Matrix{
		Policy: Policy{
			Vendor:                "canonical",
			Product:               "ubuntu_linux",
			MinLTSVersionsCovered: 2,
		},
		Targets: []Target{lts("ubuntu-22.04", "22.04")},
	}
	require.ErrorContains(t, m.Validate(), "software_lifecycle")

	m.Targets = append(m.Targets, lts("ubuntu-24.04", "24.04"))
	require.NoError(t, m.Validate())
}

func TestMatrixValidateRequiresInterimWhenPolicySaysSo(t *testing.T) {
	m := Matrix{
		Policy: Policy{
			MinLTSVersionsCovered: 2,
			IncludeLatestInterim:  true,
		},
		Targets: []Target{lts("ubuntu-22.04", "22.04"), lts("ubuntu-24.04", "24.04")},
	}
	require.ErrorContains(t, m.Validate(), "include_latest_interim")
}

func TestMatrixValidateRejectsDuplicateNaturalKeys(t *testing.T) {
	dup := lts("ubuntu-22.04-again", "22.04")
	m := Matrix{
		Policy:  Policy{MinLTSVersionsCovered: 2},
		Targets: []Target{lts("ubuntu-22.04", "22.04"), lts("ubuntu-24.04", "24.04"), dup},
	}
	require.ErrorContains(t, m.Validate(), "natural key")
}

func TestMatrixPolicyNaturalKey(t *testing.T) {
	p := Policy{Vendor: "canonical", Product: "ubuntu_linux", PolicyName: "matrix-coverage-policy"}
	require.Equal(t, "canonical|ubuntu_linux|matrix-coverage-policy", p.NaturalKey())
}

func TestLoadMatrixFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"policy":{},"tagets":[]}`), 0o600))
	_, err := LoadMatrixFile(path)
	require.ErrorContains(t, err, "parse matrix")
}

func TestMatrixTargetLookup(t *testing.T) {
	m := Matrix{Targets: []Target{lts("ubuntu-22.04", "22.04")}}
	found, ok := m.Target("ubuntu-22.04")
	require.True(t, ok)
	require.Equal(t, "22.04", found.Version)

	_, ok = m.Target("ubuntu-18.04")
	require.False(t, ok)
}

func TestRepoRootLooksLikeTheModule(t *testing.T) {
	require.FileExists(t, filepath.Join(RepoRoot(), "go.mod"))
}
