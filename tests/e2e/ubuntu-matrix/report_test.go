package ubuntumatrix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRunProjectsTargetAndFixture(t *testing.T) {
	obs := baselineObservation()
	obs.Expectation.SeedManifest = []SeedPackage{
		{Name: "vim", Arch: "amd64", State: "installed"},
	}
	started := time.Date(2026, 7, 24, 14, 2, 11, 0, time.UTC)
	completed := started.Add(36 * time.Second)

	run := NewRun(obs, Evaluate(obs), started, completed)

	require.Equal(t, "ubuntu", run.Target.DistroFamily)
	require.Equal(t, "22.04", run.Target.Version)
	require.Equal(t, SupportActive, run.Target.SupportStatus)
	require.True(t, run.Target.IsLTS)
	require.False(t, run.Target.Blocking)

	require.Equal(t, "docker.io/library/ubuntu:22.04", run.Fixture.ImageRef)
	require.Equal(t, testDigest("a"), run.Fixture.ImageDigest)
	require.Len(t, run.Fixture.SeedManifest, 1)

	require.Equal(t, "qa-ubuntu-package-matrix (ubuntu-22.04)", run.CIJobName)
	require.Equal(t, "2026-07-24T14:02:11Z", run.StartedAt)
	require.Equal(t, "2026-07-24T14:02:47Z", run.CompletedAt)
	require.Equal(t, StatusPass, run.Status)
	require.Equal(t, 4, run.ActualPackageCount)
	require.Equal(t, 3, run.ExpectedPackageCount)
	require.Equal(t, int64(36_000), run.DurationMS)
}

// When the drift-check resolved a live digest, that is what actually booted,
// so it is what the ContainerTestFixture row must record.
func TestNewRunPrefersObservedDigest(t *testing.T) {
	obs := baselineObservation()
	obs.ObservedDigest = testDigest("c")
	run := NewRun(obs, nil, time.Now(), time.Now())
	require.Equal(t, testDigest("c"), run.Fixture.ImageDigest)
}

// infra_error is never an assertion outcome: conflating a rate-limited pull
// with a collector bug would corrupt the whole signal.
func TestAsInfraErrorDropsFindings(t *testing.T) {
	obs := baselineObservation()
	now := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC)
	run := NewRun(obs, Evaluate(obs), now, now).AsInfraError("container start: pull rate limit", now)

	require.Equal(t, StatusInfraError, run.Status)
	require.Len(t, run.Findings, 1)
	require.Equal(t, SeverityInfo, run.Findings[0].Severity)
	require.Contains(t, run.Findings[0].ActualValue, "rate limit")
	require.Empty(t, run.Fixture.SeedManifest)
	require.Equal(t, "qa-ubuntu-package-matrix (ubuntu-22.04)", run.CIJobName)
}

func TestAsInfraErrorWithoutReason(t *testing.T) {
	run := NewRun(baselineObservation(), nil, time.Now(), time.Now()).AsInfraError("", time.Now())
	require.Equal(t, StatusInfraError, run.Status)
	require.Empty(t, run.Findings)
}

func testPolicy() Policy {
	return Policy{
		PolicyName:            "matrix-coverage-policy",
		Vendor:                "canonical",
		Product:               "ubuntu_linux",
		MinLTSVersionsCovered: 2,
		IncludeLatestInterim:  true,
		ReviewCadenceDays:     180,
	}
}

func TestNewPayloadUsesCIEnvironment(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "1234567890")
	t.Setenv("GITHUB_WORKFLOW", "ubuntu-package-matrix")

	run := NewRun(baselineObservation(), nil, time.Now(), time.Now())
	p := NewPayload("a1b2c3d", testPolicy(), []Run{run})
	require.Equal(t, "1234567890", p.CIRunID)
	require.Equal(t, "ubuntu-package-matrix", p.WorkflowName)
	require.Equal(t, "a1b2c3d", p.KiteCollectorVersion)
	require.Equal(t, "canonical|ubuntu_linux|matrix-coverage-policy", p.Policy.NaturalKey())
	require.Len(t, p.Runs, 1)
}

func TestNewPayloadFallsBackOutsideCI(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITHUB_WORKFLOW", "")
	p := NewPayload("unknown", testPolicy(), nil)
	require.Equal(t, "local", p.CIRunID)
	require.Equal(t, "ubuntu-package-matrix.yml", p.WorkflowName)
}

// The artifact is the durable source of truth the trusted-zone workflow_run
// job later signs and POSTs, so its shape is part of the §5.4 contract.
func TestPayloadWriteFileMatchesIngestContract(t *testing.T) {
	obs := baselineObservation()
	run := NewRun(obs, Evaluate(obs), time.Now(), time.Now())
	path := filepath.Join(t.TempDir(), "nested", "ubuntu-22.04.json")

	require.NoError(t, NewPayload("a1b2c3d", testPolicy(), []Run{run}).WriteFile(path))

	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	for _, key := range []string{
		"ci_run_id", "workflow_name", "kite_collector_version", "policy", "runs",
	} {
		require.Contains(t, decoded, key)
	}

	runs, ok := decoded["runs"].([]any)
	require.True(t, ok)
	first, ok := runs[0].(map[string]any)
	require.True(t, ok)
	for _, key := range []string{
		"target", "fixture", "ci_job_name", "started_at", "completed_at", "status",
		"expected_package_count", "actual_package_count", "parse_error_count",
		"duration_ms", "findings",
	} {
		require.Contains(t, first, key)
	}
}

func TestReportPathHonoursOverride(t *testing.T) {
	t.Setenv("KITE_MATRIX_REPORT_DIR", "/tmp/matrix-out")
	require.Equal(t, "/tmp/matrix-out/ubuntu-22.04.json", ReportPath("ubuntu-22.04"))
}

// R6: the PR summary shows a package-level expected-vs-actual diff, so a
// maintainer never has to dig through raw `go test -v` output.
func TestStepSummaryRendersPackageLevelDiff(t *testing.T) {
	obs := baselineObservation()
	obs.Packages = append(obs.Packages, pkg("zlib1g:i386", "1:1.2.11", "i386"))
	run := NewRun(obs, Evaluate(obs), time.Now(), time.Now())

	summary := StepSummary(run, "ubuntu-22.04")
	require.Contains(t, summary, "### FAIL — ubuntu-package-matrix ubuntu-22.04")
	require.Contains(t, summary, "| Finding | Severity | Package | Expected | Actual | Status |")
	require.Contains(t, summary, "multiarch_suffix_leak")
	require.Contains(t, summary, "zlib1g:i386")
	require.Contains(t, summary, "acknowledged", "waived findings stay visible")
}

func TestStepSummaryCleanRun(t *testing.T) {
	obs := baselineObservation()
	obs.Expectation.Packages = nil
	run := NewRun(obs, Evaluate(obs), time.Now(), time.Now())

	summary := StepSummary(run, "ubuntu-22.04")
	require.Contains(t, summary, "### PASS —")
	require.Contains(t, summary, "No parity findings.")
}

func TestStepSummaryTruncatesLongFindingLists(t *testing.T) {
	run := Run{Status: StatusFail}
	for range summaryFindingLimit + 4 {
		run.Findings = append(run.Findings, Finding{
			FindingType:       FindingCPEGenerationMismatch,
			Severity:          SeverityHigh,
			RemediationStatus: RemediationOpen,
		})
	}
	summary := StepSummary(run, "ubuntu-22.04")
	require.Contains(t, summary, "4 further findings omitted")
}

func TestStepSummaryInfraIcon(t *testing.T) {
	require.Contains(t,
		StepSummary(Run{Status: StatusInfraError}, "ubuntu-devel"),
		"### INFRA —",
	)
}

func TestAppendStepSummaryIsNoOpOutsideActions(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	require.NoError(t, AppendStepSummary("ignored"))
}

func TestAppendStepSummaryAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", path)

	require.NoError(t, AppendStepSummary("first\n"))
	require.NoError(t, AppendStepSummary("second\n"))

	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	require.Equal(t, "first\nsecond\n", string(raw))
}

func TestTruncate(t *testing.T) {
	require.Equal(t, "abc", truncate("abc", 5))
	require.Equal(t, "ab…", truncate("abcdef", 2))
	require.True(t, strings.HasSuffix(truncate(strings.Repeat("x", 200), 120), "…"))
}
