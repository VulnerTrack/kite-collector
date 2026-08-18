package ubuntumatrix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
)

// PackageParityFinding types — the closed enum from RFC-0149 §4.1.4. An
// unrecognised value is rejected at ingest, which is what keeps the
// "show me every cpe_generation_mismatch" query reliable.
const (
	FindingEpochVersionMismatch  = "epoch_version_mismatch"
	FindingMultiarchSuffixLeak   = "multiarch_suffix_leak"
	FindingCPEGenerationMismatch = "cpe_generation_mismatch"
	FindingPackageManagerDrift   = "package_manager_label_drift"
	FindingCountMismatch         = "count_mismatch"
	FindingEncodingError         = "encoding_error"
	FindingPurgedPackageIncluded = "purged_package_included"
	FindingBaseImageDigestDrift  = "base_image_digest_drift"
)

// Severities. `high` is reserved, per §4.1.4, for findings that would
// plausibly suppress a real CVE match — this is a security policy, not a
// generic bug-triage scale.
const (
	SeverityInfo   = "info"
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// Remediation statuses (§4.1.4).
const (
	RemediationOpen         = "open"
	RemediationAcknowledged = "acknowledged"
	RemediationFixed        = "fixed"
	RemediationWontFix      = "wontfix"
)

// Roles an expected package plays in the fixture.
const (
	RoleBaseline  = "baseline"
	RoleEpoch     = "epoch"
	RoleMultiarch = "multiarch"
	RolePurged    = "purged"
)

// Terminal PackageDiscoveryTestRun statuses (§4.1.3). `infra_error` is never
// aggregated as a pass or as a genuine parity failure.
const (
	StatusRunning    = "running"
	StatusPass       = "pass"
	StatusFail       = "fail"
	StatusInfraError = "infra_error"
)

// maxFindingsPerType bounds a systemic break (e.g. every CPE malformed) from
// producing a thousand-row payload. Truncation is never silent: an explicit
// overflow finding records how many were dropped.
const maxFindingsPerType = 20

// cpe23Shape is an independent structural check on the emitted CPE, so a
// regression inside BuildCPE23 itself cannot hide behind the derivation
// check (which uses that same function).
var cpe23Shape = regexp.MustCompile(
	`^cpe:2\.3:a:[^:]*:[^:]*:[^:]*:\*:\*:\*:\*:[^:]*:[^:]*:\*$`,
)

// epochPattern splits a Debian version into its epoch and upstream halves.
var epochPattern = regexp.MustCompile(`^([0-9]+):(.+)$`)

// Finding is one PackageParityFinding (§4.1.4).
type Finding struct {
	FindingType       string `json:"finding_type"`
	Severity          string `json:"severity"`
	PackageNameRef    string `json:"package_name_ref"`
	ExpectedValue     string `json:"expected_value"`
	ActualValue       string `json:"actual_value"`
	RemediationStatus string `json:"remediation_status"`
	DetectedAt        string `json:"detected_at"`
}

// SeedPackage is one entry of a ContainerTestFixture's seed manifest (§4.1.2).
type SeedPackage struct {
	Name  string `json:"name"`
	Arch  string `json:"arch"`
	State string `json:"state"`
}

// ExpectedPackage is a per-package assertion in a target's known-good fixture.
//
// Exact values are asserted where dpkg output is deterministic (name,
// architecture, package_manager) and patterns where upstream churn is
// expected (version, which moves with every Ubuntu security update). A
// hardcoded version string would turn every SRU into a red build.
type ExpectedPackage struct {
	Name           string   `json:"name"`
	VersionPattern string   `json:"version_pattern"`
	Roles          []string `json:"roles"`
	Architectures  []string `json:"architectures"`
	KnownIssues    []string `json:"known_issues"`
}

// HasRole reports whether this expectation carries the given role.
func (e ExpectedPackage) HasRole(role string) bool {
	return slices.Contains(e.Roles, role)
}

// Expectation is one target's whole known-good fixture.
type Expectation struct {
	Target          string            `json:"target"`
	PackageManager  string            `json:"package_manager"`
	Notes           string            `json:"notes"`
	SeedManifest    []SeedPackage     `json:"seed_manifest"`
	Packages        []ExpectedPackage `json:"packages"`
	KnownIssues     []string          `json:"known_issues"`
	MinPackageCount int               `json:"min_package_count"`
	MaxParseErrors  int               `json:"max_parse_errors"`
}

// LoadExpectation reads a target's expected fixture.
func LoadExpectation(target Target) (Expectation, error) {
	path := Path(target.ExpectedFile)
	raw, err := os.ReadFile(path) //#nosec G304 -- suite-local, non-user-supplied fixture path
	if err != nil {
		return Expectation{}, fmt.Errorf("read expectation %s: %w", path, err)
	}
	var exp Expectation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&exp); err != nil {
		return Expectation{}, fmt.Errorf("parse expectation %s: %w", path, err)
	}
	if exp.Target != target.Slug {
		return Expectation{}, fmt.Errorf(
			"expectation %s declares target %q but is wired to %q",
			path, exp.Target, target.Slug,
		)
	}
	if exp.PackageManager == "" {
		return Expectation{}, fmt.Errorf("expectation %s: package_manager is required", path)
	}
	return exp, nil
}

// Observation is everything one matrix leg produced, ready for evaluation.
type Observation struct {
	Target         Target
	Expectation    Expectation
	Now            time.Time
	ObservedDigest string
	Packages       []Package
	ParseErrors    int
}

// findingSet accumulates findings with a per-type cap so a systemic failure
// cannot produce an unbounded payload — and records what it dropped.
type findingSet struct {
	byType   map[string]int
	now      string
	findings []Finding
}

func newFindingSet(now time.Time) *findingSet {
	return &findingSet{
		byType: map[string]int{},
		now:    now.UTC().Format(time.RFC3339),
	}
}

func (f *findingSet) add(findingType, severity, pkgRef, expected, actual string) {
	f.byType[findingType]++
	if f.byType[findingType] > maxFindingsPerType {
		return
	}
	f.findings = append(f.findings, Finding{
		FindingType:       findingType,
		Severity:          severity,
		PackageNameRef:    pkgRef,
		ExpectedValue:     expected,
		ActualValue:       actual,
		RemediationStatus: RemediationOpen,
		DetectedAt:        f.now,
	})
}

// result returns the accumulated findings plus one explicit overflow finding
// per truncated type, so a capped report never reads as "that was all of it".
func (f *findingSet) result() []Finding {
	out := f.findings
	types := make([]string, 0, len(f.byType))
	for t := range f.byType {
		if f.byType[t] > maxFindingsPerType {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	for _, t := range types {
		out = append(out, Finding{
			FindingType:    FindingCountMismatch,
			Severity:       SeverityMedium,
			PackageNameRef: "",
			ExpectedValue:  fmt.Sprintf("all %s findings reported", t),
			ActualValue: fmt.Sprintf(
				"%d %s findings detected, first %d reported",
				f.byType[t], t, maxFindingsPerType,
			),
			RemediationStatus: RemediationOpen,
			DetectedAt:        f.now,
		})
	}
	return out
}

// Evaluate runs every parity check for one leg and returns the findings,
// with fixture-declared known issues already downgraded to `acknowledged`.
func Evaluate(obs Observation) []Finding {
	set := newFindingSet(obs.Now)
	managed := FilterByPackageManager(obs.Packages, obs.Expectation.PackageManager)

	checkDigestPin(set, obs)
	checkPackageManagerLabel(set, obs, managed)
	checkPackageCount(set, obs, managed)
	checkParseErrors(set, obs)
	checkNaming(set, obs.Packages)
	checkCPEGeneration(set, managed)
	checkExpectedPackages(set, obs, managed)

	return applyWaivers(obs.Expectation, set.result())
}

// checkDigestPin turns base-image drift — and the absence of a pin at all —
// into a reviewable event rather than a silent change of test input (R3).
//
// The two conditions are separate facts and carry separate severities:
//
//   - Not pinned yet is a posture statement, not a supply-chain event. It is
//     the deliberate pre-Phase-4 shipping state (§10.4), and RequirePin
//     already makes `blocking ⇒ pinned` a build-breaking invariant, so a leg
//     that can block a PR is never unpinned. Reported at `info`: still
//     emitted, ingested and shown in the PR summary, so it never silently
//     passes as reviewed — but it does not fail the leg. Failing here would
//     paint every informational leg permanently red over a configuration
//     state the rollout plan itself calls for, which is how a real finding
//     later gets ignored (§4.2.3).
//   - A pin that no longer resolves to the same digest is the reviewable
//     event R3 requires to fail loudly.
func checkDigestPin(set *findingSet, obs Observation) {
	if !obs.Target.Pinned() {
		set.add(
			FindingBaseImageDigestDrift, SeverityInfo, "",
			"a pinned sha256: digest for "+obs.Target.BaseImageRef,
			"unpinned floating tag "+obs.Target.BaseImageRef,
		)
		return
	}

	if obs.ObservedDigest == "" || obs.ObservedDigest == obs.Target.ImageDigest {
		return
	}

	severity := SeverityMedium
	if obs.Target.SupportStatus == SupportInterim {
		// `devel` is a rolling tag by definition; its drift is the
		// early-warning signal (R7), not a defect.
		severity = SeverityInfo
	}
	set.add(
		FindingBaseImageDigestDrift, severity, "",
		obs.Target.ImageDigest, obs.ObservedDigest,
	)
}

// checkPackageManagerLabel guards the cross-stack contract called out in
// §2.1: the Go collector emits "dpkg" while downstream Python fixtures have
// assumed "apt". Nothing else in either language runs the real value through
// the pipeline, so this is the only place that drift would surface.
func checkPackageManagerLabel(set *findingSet, obs Observation, managed []Package) {
	if len(managed) > 0 || len(obs.Packages) == 0 {
		return
	}
	labels := map[string]struct{}{}
	for _, p := range obs.Packages {
		labels[p.PackageManager] = struct{}{}
	}
	got := make([]string, 0, len(labels))
	for l := range labels {
		got = append(got, l)
	}
	slices.Sort(got)
	set.add(
		FindingPackageManagerDrift, SeverityHigh, "",
		obs.Expectation.PackageManager, strings.Join(got, ","),
	)
}

func checkPackageCount(set *findingSet, obs Observation, managed []Package) {
	if len(managed) >= obs.Expectation.MinPackageCount {
		return
	}
	set.add(
		FindingCountMismatch, SeverityMedium, "",
		fmt.Sprintf(">= %d %s packages", obs.Expectation.MinPackageCount,
			obs.Expectation.PackageManager),
		fmt.Sprintf("%d", len(managed)),
	)
}

func checkParseErrors(set *findingSet, obs Observation) {
	if obs.ParseErrors <= obs.Expectation.MaxParseErrors {
		return
	}
	set.add(
		FindingEncodingError, SeverityMedium, "",
		fmt.Sprintf("<= %d per-line parse errors", obs.Expectation.MaxParseErrors),
		fmt.Sprintf("%d", obs.ParseErrors),
	)
}

// checkNaming covers the two ways a discovered name can be structurally
// wrong: an architecture suffix leaking into the package name (which would
// silently break every downstream CPE match), and non-printable or invalid
// UTF-8 text from a locale-dependent dpkg output change.
func checkNaming(set *findingSet, pkgs []Package) {
	seenLeak := map[string]bool{}
	for _, p := range pkgs {
		if strings.Contains(p.SoftwareName, ":") && !seenLeak[p.SoftwareName] {
			seenLeak[p.SoftwareName] = true
			base, _, _ := strings.Cut(p.SoftwareName, ":")
			set.add(
				FindingMultiarchSuffixLeak, SeverityHigh, p.SoftwareName,
				base, p.SoftwareName,
			)
		}
		if field, value, ok := firstUnprintable(p); ok {
			set.add(
				FindingEncodingError, SeverityMedium, p.SoftwareName,
				"printable UTF-8 "+field,
				fmt.Sprintf("%q", value),
			)
		}
	}
}

func firstUnprintable(p Package) (field, value string, found bool) {
	for _, candidate := range []struct{ name, value string }{
		{"software_name", p.SoftwareName},
		{"version", p.Version},
		{"architecture", p.Architecture},
	} {
		if !utf8.ValidString(candidate.value) || hasControlRune(candidate.value) {
			return candidate.name, candidate.value, true
		}
	}
	return "", "", false
}

func hasControlRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// checkCPEGeneration verifies the field this RFC exists to protect: a
// malformed cpe23 does not crash anything, it silently stops matching CVEs
// in cpe_matching_steps.py. Two independent assertions run — one structural
// (regexp), one derivational (recompute from the observed name/version/arch)
// — so neither a collector-side wiring bug nor a BuildCPE23 regression can
// hide behind the other.
func checkCPEGeneration(set *findingSet, managed []Package) {
	for _, p := range managed {
		if p.CPE23 == "" {
			set.add(
				FindingCPEGenerationMismatch, SeverityHigh, p.Key(),
				"a non-empty CPE 2.3 string", "",
			)
			continue
		}
		if !cpe23Shape.MatchString(p.CPE23) {
			set.add(
				FindingCPEGenerationMismatch, SeverityHigh, p.Key(),
				"cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:<target_sw>:<target_hw>:*",
				p.CPE23,
			)
			continue
		}
		want := software.BuildCPE23WithArch(p.Vendor, p.SoftwareName, p.Version, p.Architecture)
		if p.CPE23 != want {
			set.add(
				FindingCPEGenerationMismatch, SeverityHigh, p.Key(), want, p.CPE23,
			)
		}
	}
}

func checkExpectedPackages(set *findingSet, obs Observation, managed []Package) {
	byName := IndexByName(managed)
	allByName := IndexByName(obs.Packages)

	for _, want := range obs.Expectation.Packages {
		if want.HasRole(RolePurged) {
			checkPurged(set, want, allByName)
			continue
		}
		found := byName[want.Name]
		if len(found) == 0 {
			reportMissing(set, obs, want, allByName[want.Name])
			continue
		}
		checkArchitectures(set, want, found)
		checkVersions(set, want, found)
		checkEpoch(set, want, found)
	}
}

// reportMissing distinguishes "discovery lost the package entirely" from
// "discovery found it but labelled it with the wrong package manager". Both
// suppress downstream CVE matching, but only the second is label drift, and
// conflating them would send a maintainer hunting the wrong bug.
func reportMissing(set *findingSet, obs Observation, want ExpectedPackage, anyManager []Package) {
	if len(anyManager) > 0 {
		set.add(
			FindingPackageManagerDrift, SeverityHigh, want.Name,
			obs.Expectation.PackageManager, anyManager[0].PackageManager,
		)
		return
	}
	set.add(
		FindingCountMismatch, SeverityHigh, want.Name,
		"present in "+obs.Expectation.PackageManager+" output", "absent",
	)
}

// checkPurged asserts a package removed during seeding does not reappear as
// installed. A phantom row here is a phantom CVE exposure downstream.
func checkPurged(set *findingSet, want ExpectedPackage, allByName map[string][]Package) {
	found := allByName[want.Name]
	if len(found) == 0 {
		return
	}
	set.add(
		FindingPurgedPackageIncluded, SeverityHigh, want.Name,
		"absent (purged during seeding)",
		fmt.Sprintf("%s %s (%s)", found[0].SoftwareName, found[0].Version, found[0].Architecture),
	)
}

// checkArchitectures is the multi-arch assertion: after `dpkg
// --add-architecture i386`, one package name legitimately carries several
// rows, and each must survive discovery as its own distinctly-addressable
// row rather than being collapsed or suffix-mangled.
func checkArchitectures(set *findingSet, want ExpectedPackage, found []Package) {
	if len(want.Architectures) == 0 {
		return
	}
	got := make([]string, 0, len(found))
	for _, p := range found {
		got = append(got, p.Architecture)
	}
	slices.Sort(got)
	for _, arch := range want.Architectures {
		if slices.Contains(got, arch) {
			continue
		}
		set.add(
			FindingCountMismatch, SeverityHigh, want.Name+"|"+arch,
			"architecture "+arch+" present", strings.Join(got, ","),
		)
	}
}

func checkVersions(set *findingSet, want ExpectedPackage, found []Package) {
	if want.VersionPattern == "" {
		return
	}
	re, err := regexp.Compile(want.VersionPattern)
	if err != nil {
		set.add(
			FindingCountMismatch, SeverityMedium, want.Name,
			"a compilable version_pattern", want.VersionPattern,
		)
		return
	}
	for _, p := range found {
		if re.MatchString(p.Version) {
			continue
		}
		// Deliberately count_mismatch, never epoch_version_mismatch, even
		// for an epoch-role package: a fixture that waives the known CPE
		// epoch mangle must not also silently waive "the seeded package
		// stopped carrying an epoch at all", which is a different — and
		// unwaived — regression.
		set.add(FindingCountMismatch, SeverityHigh, p.Key(), want.VersionPattern, p.Version)
	}
}

// checkEpoch is the epoch-version assertion R2 calls for. `dpkg-query` emits
// `2:9.0.2114-1`; the CPE builder must split the epoch off rather than merely
// delete the colon — deletion fuses the epoch digit into the version
// (`29.0.2114-1`), a string that will never match NVD's `9.0.2114`. That
// false-negative CVE match shipped for real until software/cpe.go learned to
// split epochs; this live assertion is what keeps it from coming back.
func checkEpoch(set *findingSet, want ExpectedPackage, found []Package) {
	if !want.HasRole(RoleEpoch) {
		return
	}
	for _, p := range found {
		m := epochPattern.FindStringSubmatch(p.Version)
		if m == nil {
			continue
		}
		upstream := m[2]
		wantCPE := software.BuildCPE23WithArch(p.Vendor, p.SoftwareName, upstream, p.Architecture)
		if p.CPE23 == wantCPE {
			continue
		}
		set.add(FindingEpochVersionMismatch, SeverityHigh, p.Key(), wantCPE, p.CPE23)
	}
}

// applyWaivers downgrades findings the fixture explicitly acknowledges. A
// waived finding is still emitted — it stays queryable in the ontology and
// visible in the PR summary — it simply does not fail the leg. Removing the
// annotation from the fixture is how a known issue becomes blocking again.
func applyWaivers(exp Expectation, findings []Finding) []Finding {
	perPackage := map[string][]string{}
	for _, p := range exp.Packages {
		if len(p.KnownIssues) > 0 {
			perPackage[p.Name] = p.KnownIssues
		}
	}

	for i := range findings {
		f := &findings[i]
		if slices.Contains(exp.KnownIssues, f.FindingType) {
			f.RemediationStatus = RemediationAcknowledged
			continue
		}
		name, _, _ := strings.Cut(f.PackageNameRef, "|")
		if slices.Contains(perPackage[name], f.FindingType) {
			f.RemediationStatus = RemediationAcknowledged
		}
	}
	return findings
}

// StatusFor derives the terminal PackageDiscoveryTestRun status. Per
// §4.2.2 any open finding at severity >= low fails the leg; `info` findings
// and acknowledged known issues are reported without failing it.
func StatusFor(findings []Finding) string {
	for _, f := range findings {
		if f.RemediationStatus != RemediationOpen {
			continue
		}
		if f.Severity == SeverityInfo {
			continue
		}
		return StatusFail
	}
	return StatusPass
}
