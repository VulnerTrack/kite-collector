package ubuntumatrix

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func pinnedTarget() Target {
	t := lts("ubuntu-22.04", "22.04")
	t.ImageDigest = testDigest("a")
	return t
}

// baselineExpectation mirrors the shipped fixtures: an epoch package guarding
// the CPE epoch split, a multi-arch package, a plain baseline, and a purge
// probe. No waiver ships since the epoch-splitting fix in software/cpe.go;
// tests that exercise the waiver path add it explicitly.
func baselineExpectation() Expectation {
	return Expectation{
		Target:          "ubuntu-22.04",
		PackageManager:  "dpkg",
		MinPackageCount: 3,
		MaxParseErrors:  0,
		Packages: []ExpectedPackage{
			{
				Name:           "vim",
				Roles:          []string{RoleEpoch},
				Architectures:  []string{"amd64"},
				VersionPattern: `^[0-9]+:`,
			},
			{
				Name:          "libc6",
				Roles:         []string{RoleMultiarch},
				Architectures: []string{"amd64", "i386"},
			},
			{Name: "dpkg", Roles: []string{RoleBaseline}, Architectures: []string{"amd64"}},
			{Name: "hello", Roles: []string{RolePurged}},
		},
	}
}

func baselinePackages() []Package {
	return []Package{
		pkg("vim", "2:9.0.2114-1ubuntu1", "amd64"),
		pkg("libc6", "2.35-0ubuntu3.8", "amd64"),
		pkg("libc6", "2.35-0ubuntu3.8", "i386"),
		pkg("dpkg", "1.21.1ubuntu2.3", "amd64"),
	}
}

func baselineObservation() Observation {
	return Observation{
		Now:         time.Date(2026, 7, 24, 14, 2, 11, 0, time.UTC),
		Target:      pinnedTarget(),
		Expectation: baselineExpectation(),
		Packages:    baselinePackages(),
	}
}

func findingsOfType(findings []Finding, findingType string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.FindingType == findingType {
			out = append(out, f)
		}
	}
	return out
}

// Since the epoch-splitting fix in software/cpe.go the happy path is
// genuinely clean: the collector derives `9.0.2114` from `2:9.0.2114`, so no
// epoch finding fires at all and the leg passes without any waiver.
func TestEvaluateCleanRunPasses(t *testing.T) {
	findings := Evaluate(baselineObservation())
	require.Equal(t, StatusPass, StatusFor(findings))
	require.Empty(t, findingsOfType(findings, FindingEpochVersionMismatch),
		"the fixed CPE builder must not trip its own epoch assertion")
}

// The pre-fix collector deleted the epoch colon, so `2:9.0.2114-1` became
// version `29.0.2114-1` — a string NVD will never match. If that shape ever
// comes back, it fails the leg: there is no fixture waiver any more.
func TestEvaluateEpochMangleFailsWhenNotWaived(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[0] = mangledPkg("vim", "2:9.0.2114-1ubuntu1", "amd64")

	findings := Evaluate(obs)
	require.Equal(t, StatusFail, StatusFor(findings))

	epoch := findingsOfType(findings, FindingEpochVersionMismatch)
	require.Len(t, epoch, 1)
	require.Equal(t, RemediationOpen, epoch[0].RemediationStatus)
	require.Contains(t, epoch[0].ExpectedValue, ":vim:9.0.2114-1ubuntu1:")
	require.Contains(t, epoch[0].ActualValue, ":vim:29.0.2114-1ubuntu1:")
}

// A waived finding is still emitted and downgraded to acknowledged — but the
// waiver is no longer a green light: the harness also rebuilds the CPE with
// the fixed builder, and that unwaived cpe_generation_mismatch keeps a
// re-mangling collector failing the leg.
func TestEvaluateWaivedEpochMangleStaysVisibleButStillFails(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[0] = mangledPkg("vim", "2:9.0.2114-1ubuntu1", "amd64")
	obs.Expectation.Packages[0].KnownIssues = []string{FindingEpochVersionMismatch}

	findings := Evaluate(obs)

	epoch := findingsOfType(findings, FindingEpochVersionMismatch)
	require.Len(t, epoch, 1, "the waived finding must still be reported")
	require.Equal(t, RemediationAcknowledged, epoch[0].RemediationStatus)
	require.Equal(t, SeverityHigh, epoch[0].Severity)
	require.Equal(t, "vim|amd64", epoch[0].PackageNameRef)
	require.Equal(t, "2026-07-24T14:02:11Z", epoch[0].DetectedAt)

	cpe := findingsOfType(findings, FindingCPEGenerationMismatch)
	require.Len(t, cpe, 1)
	require.Equal(t, RemediationOpen, cpe[0].RemediationStatus)
	require.Equal(t, StatusFail, StatusFor(findings))
}

// A package that stops carrying an epoch is a different regression from the
// CPE mangle, and must not be swallowed by the same waiver.
func TestEvaluateLostEpochIsNotWaived(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[0] = pkg("vim", "9.0.2114-1ubuntu1", "amd64")

	findings := Evaluate(obs)
	require.Equal(t, StatusFail, StatusFor(findings))
	require.Empty(t, findingsOfType(findings, FindingEpochVersionMismatch))

	counts := findingsOfType(findings, FindingCountMismatch)
	require.Len(t, counts, 1)
	require.Equal(t, RemediationOpen, counts[0].RemediationStatus)
	require.Equal(t, `^[0-9]+:`, counts[0].ExpectedValue)
}

// If the architecture suffix ever leaks into ${Package}, BuildCPE23 emits a
// product no CVE will match — a false negative, not a crash.
func TestEvaluateMultiarchSuffixLeak(t *testing.T) {
	obs := baselineObservation()
	obs.Packages = append(obs.Packages, pkg("zlib1g:i386", "1:1.2.11", "i386"))

	findings := Evaluate(obs)
	leaks := findingsOfType(findings, FindingMultiarchSuffixLeak)
	require.Len(t, leaks, 1)
	require.Equal(t, SeverityHigh, leaks[0].Severity)
	require.Equal(t, "zlib1g", leaks[0].ExpectedValue)
	require.Equal(t, "zlib1g:i386", leaks[0].ActualValue)
	require.Equal(t, StatusFail, StatusFor(findings))
}

func TestEvaluateMissingArchitecture(t *testing.T) {
	obs := baselineObservation()
	obs.Packages = []Package{
		pkg("vim", "2:9.0.2114-1ubuntu1", "amd64"),
		pkg("libc6", "2.35-0ubuntu3.8", "amd64"),
		pkg("dpkg", "1.21.1ubuntu2.3", "amd64"),
	}

	findings := Evaluate(obs)
	counts := findingsOfType(findings, FindingCountMismatch)
	require.Len(t, counts, 1)
	require.Equal(t, "libc6|i386", counts[0].PackageNameRef)
	require.Equal(t, StatusFail, StatusFor(findings))
}

// A purged package reappearing as installed is a phantom CVE exposure.
func TestEvaluatePurgedPackageIncluded(t *testing.T) {
	obs := baselineObservation()
	obs.Packages = append(obs.Packages, pkg("hello", "2.10-2build1", "amd64"))

	findings := Evaluate(obs)
	purged := findingsOfType(findings, FindingPurgedPackageIncluded)
	require.Len(t, purged, 1)
	require.Equal(t, SeverityHigh, purged[0].Severity)
	require.Equal(t, StatusFail, StatusFor(findings))
}

// §2.1's live cross-stack inconsistency: the Go collector emits "dpkg" while
// downstream Python fixtures assumed "apt". Nothing else runs the real value
// through the pipeline.
func TestEvaluatePackageManagerDriftForEveryPackage(t *testing.T) {
	obs := baselineObservation()
	for i := range obs.Packages {
		obs.Packages[i].PackageManager = "apt"
	}

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingPackageManagerDrift)
	require.NotEmpty(t, drift)
	require.Equal(t, "dpkg", drift[0].ExpectedValue)
	require.Equal(t, "apt", drift[0].ActualValue)
	require.Equal(t, StatusFail, StatusFor(findings))
}

func TestEvaluatePackageManagerDriftForOnePackage(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[3].PackageManager = "apt"

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingPackageManagerDrift)
	require.Len(t, drift, 1)
	require.Equal(t, "dpkg", drift[0].PackageNameRef)
	require.Equal(t, "apt", drift[0].ActualValue)
}

func TestEvaluateCPEGenerationMismatch(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[3].CPE23 = "cpe:2.3:a:*:dpkg:WRONG:*:*:*:*:*:amd64:*"

	findings := Evaluate(obs)
	mismatch := findingsOfType(findings, FindingCPEGenerationMismatch)
	require.Len(t, mismatch, 1)
	require.Equal(t, "dpkg|amd64", mismatch[0].PackageNameRef)
	require.Equal(t, StatusFail, StatusFor(findings))
}

func TestEvaluateCPEStructuralBreak(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[3].CPE23 = "dpkg-1.21.1"

	findings := Evaluate(obs)
	mismatch := findingsOfType(findings, FindingCPEGenerationMismatch)
	require.Len(t, mismatch, 1)
	require.Contains(t, mismatch[0].ExpectedValue, "cpe:2.3:a:")
}

func TestEvaluateEmptyCPE(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[3].CPE23 = ""

	findings := Evaluate(obs)
	require.Len(t, findingsOfType(findings, FindingCPEGenerationMismatch), 1)
}

func TestEvaluateCountMismatch(t *testing.T) {
	obs := baselineObservation()
	obs.Expectation.MinPackageCount = 500

	findings := Evaluate(obs)
	counts := findingsOfType(findings, FindingCountMismatch)
	require.NotEmpty(t, counts)
	require.Equal(t, ">= 500 dpkg packages", counts[0].ExpectedValue)
	require.Equal(t, "4", counts[0].ActualValue)
}

func TestEvaluateParseErrorsExceedBudget(t *testing.T) {
	obs := baselineObservation()
	obs.ParseErrors = 3

	findings := Evaluate(obs)
	enc := findingsOfType(findings, FindingEncodingError)
	require.Len(t, enc, 1)
	require.Equal(t, "3", enc[0].ActualValue)
}

func TestEvaluateEncodingError(t *testing.T) {
	obs := baselineObservation()
	obs.Packages[3].Version = "1.21.1\x00ubuntu"
	obs.Packages[3].CPE23 = "cpe:2.3:a:*:dpkg:1.21.1ubuntu:*:*:*:*:*:amd64:*"

	findings := Evaluate(obs)
	require.NotEmpty(t, findingsOfType(findings, FindingEncodingError))
}

// R3: an unpinned leg never silently passes as if it had been reviewed — the
// finding is always emitted. It is `info` rather than leg-failing because
// shipping unpinned is the deliberate pre-Phase-4 posture (§10.4) and
// RequirePin already blocks `blocking` without a pin; failing here would make
// every informational leg permanently red over an expected configuration
// state. Drift away from an existing pin still fails (TestEvaluateDigestDrift).
func TestEvaluateUnpinnedTargetReportsDrift(t *testing.T) {
	obs := baselineObservation()
	obs.Target.ImageDigest = ""

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingBaseImageDigestDrift)
	require.Len(t, drift, 1)
	require.Equal(t, SeverityInfo, drift[0].Severity)
	require.Equal(t, RemediationOpen, drift[0].RemediationStatus)
	require.Equal(t, StatusPass, StatusFor(findings))
}

// The shipped matrix is entirely unpinned (§10.4), so a healthy container must
// not report `fail` on that basis alone — otherwise every LTS leg is red on
// day one and the Phase 3 signal is noise before it is ever read.
func TestEvaluateShippedUnpinnedPostureStillPasses(t *testing.T) {
	m, err := LoadMatrix()
	require.NoError(t, err)

	for _, target := range m.Targets {
		if target.Pinned() {
			continue
		}
		obs := baselineObservation()
		obs.Target = target
		obs.ObservedDigest = testDigest("a")

		require.Equalf(t, StatusPass, StatusFor(Evaluate(obs)),
			"unpinned shipped target %s must not fail on pin posture alone",
			target.Slug)
	}
}

func TestEvaluateDigestDrift(t *testing.T) {
	obs := baselineObservation()
	obs.ObservedDigest = testDigest("c")

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingBaseImageDigestDrift)
	require.Len(t, drift, 1)
	require.Equal(t, testDigest("a"), drift[0].ExpectedValue)
	require.Equal(t, testDigest("c"), drift[0].ActualValue)
}

// `devel` is a rolling tag: its drift is the early-warning signal (R7), so it
// is recorded at info severity and does not fail the informational leg.
func TestEvaluateInterimDigestDriftIsInformational(t *testing.T) {
	obs := baselineObservation()
	obs.Target.SupportStatus = SupportInterim
	obs.Target.IsLTS = false
	obs.ObservedDigest = testDigest("c")

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingBaseImageDigestDrift)
	require.Len(t, drift, 1)
	require.Equal(t, SeverityInfo, drift[0].Severity)
	require.Equal(t, StatusPass, StatusFor(findings))
}

// A systemic break must not produce an unbounded payload — and truncation
// must never read as "that was all of it".
func TestEvaluateCapsFindingsAndRecordsOverflow(t *testing.T) {
	obs := baselineObservation()
	obs.Expectation.Packages = nil
	obs.Packages = nil
	for i := range maxFindingsPerType + 5 {
		p := pkg("pkg"+strconv.Itoa(i), "1.0", "amd64")
		p.CPE23 = "cpe:2.3:a:*:wrong:1.0:*:*:*:*:*:amd64:*"
		obs.Packages = append(obs.Packages, p)
	}

	findings := Evaluate(obs)
	require.Len(t, findingsOfType(findings, FindingCPEGenerationMismatch), maxFindingsPerType)

	overflow := findingsOfType(findings, FindingCountMismatch)
	require.NotEmpty(t, overflow)
	require.Contains(t, overflow[len(overflow)-1].ActualValue, "25 cpe_generation_mismatch findings detected")
}

// A target-wide waiver covers every finding of that type.
func TestApplyWaiversTargetWide(t *testing.T) {
	obs := baselineObservation()
	obs.Target.ImageDigest = ""
	obs.Expectation.KnownIssues = []string{FindingBaseImageDigestDrift}

	findings := Evaluate(obs)
	drift := findingsOfType(findings, FindingBaseImageDigestDrift)
	require.Len(t, drift, 1)
	require.Equal(t, RemediationAcknowledged, drift[0].RemediationStatus)
	require.Equal(t, StatusPass, StatusFor(findings))
}

func TestStatusForIgnoresInfoAndAcknowledged(t *testing.T) {
	require.Equal(t, StatusPass, StatusFor(nil))
	require.Equal(t, StatusPass, StatusFor([]Finding{
		{Severity: SeverityInfo, RemediationStatus: RemediationOpen},
		{Severity: SeverityHigh, RemediationStatus: RemediationAcknowledged},
		{Severity: SeverityHigh, RemediationStatus: RemediationWontFix},
	}))
	require.Equal(t, StatusFail, StatusFor([]Finding{
		{Severity: SeverityLow, RemediationStatus: RemediationOpen},
	}))
}

func TestExpectedPackageHasRole(t *testing.T) {
	e := ExpectedPackage{Roles: []string{RoleEpoch, RoleBaseline}}
	require.True(t, e.HasRole(RoleEpoch))
	require.False(t, e.HasRole(RolePurged))
}

func TestLoadExpectationRejectsTargetMismatch(t *testing.T) {
	target := lts("ubuntu-24.04", "24.04")
	target.ExpectedFile = "fixtures/expected/ubuntu-22.04.expected.json"
	_, err := LoadExpectation(target)
	require.ErrorContains(t, err, "declares target")
}
