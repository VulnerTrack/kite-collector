package ubuntumatrix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// summaryFindingLimit bounds how many findings the PR step summary renders
// inline. The full set always reaches the JSON artifact; the summary is a
// triage surface, not the record.
const summaryFindingLimit = 15

// TargetPayload is the OSDistributionTarget projection carried in a result
// POST (§5.4). Sent per run rather than as a separate registry call so a
// single artifact replay can rebuild every dimension row.
type TargetPayload struct {
	DistroFamily  string `json:"distro_family"`
	Version       string `json:"version"`
	Codename      string `json:"codename"`
	Architecture  string `json:"architecture"`
	BaseImageRef  string `json:"base_image_ref"`
	EOLDate       string `json:"eol_date"`
	SupportStatus string `json:"support_status"`
	IsLTS         bool   `json:"is_lts"`
	Blocking      bool   `json:"blocking"`
}

// FixturePayload is the ContainerTestFixture projection (§4.1.2).
type FixturePayload struct {
	ImageRef       string        `json:"image_ref"`
	ImageDigest    string        `json:"image_digest"`
	DockerfilePath string        `json:"dockerfile_path"`
	SeedManifest   []SeedPackage `json:"seed_manifest"`
}

// Run is one PackageDiscoveryTestRun (§4.1.3) as reported to the ingest API.
type Run struct {
	Target               TargetPayload  `json:"target"`
	Fixture              FixturePayload `json:"fixture"`
	CIJobName            string         `json:"ci_job_name"`
	StartedAt            string         `json:"started_at"`
	CompletedAt          string         `json:"completed_at"`
	Status               string         `json:"status"`
	Findings             []Finding      `json:"findings"`
	ExpectedPackageCount int            `json:"expected_package_count"`
	ActualPackageCount   int            `json:"actual_package_count"`
	ParseErrorCount      int            `json:"parse_error_count"`
	DurationMS           int64          `json:"duration_ms"`
}

// Payload is the request body of POST /kite-collector/package-matrix-result.
//
// The policy travels with the results rather than being configured
// separately on the worker: targets.json is where coverage is actually
// decided, so shipping it alongside keeps the ontology's
// DistributionSupportPolicy from drifting away from the file that governs
// what really ran.
type Payload struct {
	CIRunID              string `json:"ci_run_id"`
	WorkflowName         string `json:"workflow_name"`
	KiteCollectorVersion string `json:"kite_collector_version"`
	Policy               Policy `json:"policy"`
	Runs                 []Run  `json:"runs"`
}

// NewRun assembles the reportable record for one leg.
//
// The status is derived from the findings rather than passed in, so there is
// exactly one place that decides pass/fail; an infra_error is set by the
// caller afterwards via AsInfraError, because that outcome is not an
// assertion result at all (§4.2.2).
func NewRun(obs Observation, findings []Finding, started, completed time.Time) Run {
	t := obs.Target
	return Run{
		Target: TargetPayload{
			DistroFamily:  t.DistroFamily,
			Version:       t.Version,
			Codename:      t.Codename,
			Architecture:  t.Architecture,
			BaseImageRef:  t.BaseImageRef,
			EOLDate:       t.EOLDate,
			SupportStatus: t.SupportStatus,
			IsLTS:         t.IsLTS,
			Blocking:      t.Blocking,
		},
		Fixture: FixturePayload{
			ImageRef:       t.BaseImageRef,
			ImageDigest:    firstNonEmpty(obs.ObservedDigest, t.ImageDigest),
			DockerfilePath: t.SeedScript,
			SeedManifest:   obs.Expectation.SeedManifest,
		},
		CIJobName:            JobName(t.Slug),
		StartedAt:            started.UTC().Format(time.RFC3339),
		CompletedAt:          completed.UTC().Format(time.RFC3339),
		Status:               StatusFor(findings),
		Findings:             findings,
		ExpectedPackageCount: obs.Expectation.MinPackageCount,
		ActualPackageCount: len(FilterByPackageManager(
			obs.Packages, obs.Expectation.PackageManager,
		)),
		ParseErrorCount: obs.ParseErrors,
		DurationMS:      completed.Sub(started).Milliseconds(),
	}
}

// AsInfraError rewrites a run as an infrastructure failure. A container
// pull, boot or exec timeout is never a parity outcome: conflating "Docker
// Hub was rate-limited" with "the collector has a bug" would corrupt the
// entire signal this suite exists to produce (§4.2.2).
func (r Run) AsInfraError(reason string, now time.Time) Run {
	r.Status = StatusInfraError
	r.CompletedAt = now.UTC().Format(time.RFC3339)
	r.Findings = nil
	r.Fixture.SeedManifest = nil
	if reason != "" {
		r.Findings = []Finding{{
			FindingType:       FindingCountMismatch,
			Severity:          SeverityInfo,
			ExpectedValue:     "the leg to complete",
			ActualValue:       truncate(reason, 512),
			RemediationStatus: RemediationOpen,
			DetectedAt:        now.UTC().Format(time.RFC3339),
		}}
	}
	return r
}

// JobName mirrors the GitHub Actions display name for a matrix leg, which is
// what PackageDiscoveryTestRun.ci_job_name records (§4.1.3).
func JobName(slug string) string {
	return "qa-ubuntu-package-matrix (" + slug + ")"
}

// NewPayload builds a result envelope from CI environment metadata.
func NewPayload(version string, policy Policy, runs []Run) Payload {
	return Payload{
		CIRunID:              envOr("GITHUB_RUN_ID", "local"),
		WorkflowName:         envOr("GITHUB_WORKFLOW", "ubuntu-package-matrix.yml"),
		KiteCollectorVersion: version,
		Policy:               policy,
		Runs:                 runs,
	}
}

// WriteFile persists the payload as the run artifact the trusted-zone
// workflow_run job later signs and POSTs. Ingestion is decoupled and
// best-effort by design: this file is the durable source of truth, so a
// worker outage delays observability without ever blocking a merge.
func (p Payload) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write report %s: %w", path, err)
	}
	return nil
}

// ReportPath is where a leg's artifact lands. Overridable so a CI job can
// collect all four legs into one uploaded directory.
func ReportPath(slug string) string {
	dir := envOr("KITE_MATRIX_REPORT_DIR", filepath.Join(Dir(), ".matrix-reports"))
	return filepath.Join(dir, slug+".json")
}

// StepSummary renders R6's structured, package-level expected-vs-actual diff
// in the PR check output, reusing the kite-qa-suite composite action's
// existing step-summary convention so a maintainer never has to open raw
// `go test -v` output to learn which package mismatched.
func StepSummary(run Run, slug string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### %s — ubuntu-package-matrix %s\n\n", statusIcon(run.Status), slug)
	b.WriteString("| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Image | `%s` |\n", run.Fixture.ImageRef)
	fmt.Fprintf(&b, "| Digest | `%s` |\n", orDash(run.Fixture.ImageDigest))
	fmt.Fprintf(&b, "| Result | `%s` |\n", run.Status)
	fmt.Fprintf(&b, "| Packages | %d discovered (expected >= %d) |\n",
		run.ActualPackageCount, run.ExpectedPackageCount)
	fmt.Fprintf(&b, "| Parse errors | %d |\n", run.ParseErrorCount)
	fmt.Fprintf(&b, "| Duration | %dms |\n", run.DurationMS)
	b.WriteString("\n")

	if len(run.Findings) == 0 {
		b.WriteString("No parity findings.\n\n")
		return b.String()
	}

	b.WriteString("| Finding | Severity | Package | Expected | Actual | Status |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	shown := run.Findings
	if len(shown) > summaryFindingLimit {
		shown = shown[:summaryFindingLimit]
	}
	for _, f := range shown {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | `%s` | `%s` | %s |\n",
			f.FindingType, f.Severity, orDash(f.PackageNameRef),
			orDash(truncate(f.ExpectedValue, 120)),
			orDash(truncate(f.ActualValue, 120)),
			f.RemediationStatus,
		)
	}
	if len(run.Findings) > summaryFindingLimit {
		fmt.Fprintf(&b, "\n_%d further findings omitted; see the uploaded JSON artifact._\n",
			len(run.Findings)-summaryFindingLimit)
	}
	b.WriteString("\n")
	return b.String()
}

// AppendStepSummary writes markdown to $GITHUB_STEP_SUMMARY when running
// under Actions, and is a no-op locally.
func AppendStepSummary(markdown string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path supplied by the Actions runner
	if err != nil {
		return fmt.Errorf("open step summary: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(markdown); err != nil {
		return fmt.Errorf("write step summary: %w", err)
	}
	return nil
}

func statusIcon(status string) string {
	switch status {
	case StatusPass:
		return "PASS"
	case StatusInfraError:
		return "INFRA"
	default:
		return "FAIL"
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
