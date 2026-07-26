// Package ubuntumatrix implements RFC-0149's Ubuntu multi-version container
// test matrix for kite-collector's OS package discovery.
//
// The package is split so that the container-driving code lives behind the
// `e2e` build tag (matrix_test.go) while the declarative model, the parity
// checks, and the result-report builder stay untagged. That way `go vet`,
// `golangci-lint` and the default `make test` all cover the classification
// logic — the part that decides whether a red leg is a real regression —
// without needing a Docker daemon.
package ubuntumatrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Support statuses an OSDistributionTarget may hold (RFC-0149 §4.1.1). The
// enum is closed: an unknown value is a configuration error, not a new state.
const (
	SupportActive  = "active"
	SupportLegacy  = "legacy"
	SupportInterim = "interim"
	SupportRetired = "retired"
)

// digestPattern matches a fully-resolved OCI content digest. A bare tag is
// deliberately not accepted: the whole supply-chain-drift claim in RFC-0149
// §6.5 rests on this field being a real, reviewable digest.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var validSupportStatus = map[string]bool{
	SupportActive:  true,
	SupportLegacy:  true,
	SupportInterim: true,
	SupportRetired: true,
}

// Target is one OSDistributionTarget (RFC-0149 §4.1.1) — the abstract matrix
// cell, independent of which concrete image currently realizes it.
type Target struct {
	Slug          string `json:"slug"`
	DistroFamily  string `json:"distro_family"`
	Version       string `json:"version"`
	Codename      string `json:"codename"`
	Architecture  string `json:"architecture"`
	EOLDate       string `json:"eol_date"`
	SupportStatus string `json:"support_status"`
	BaseImageRef  string `json:"base_image_ref"`
	ImageDigest   string `json:"image_digest"`
	SeedScript    string `json:"seed_script"`
	ExpectedFile  string `json:"expected_file"`
	IsLTS         bool   `json:"is_lts"`
	Blocking      bool   `json:"blocking"`
}

// NaturalKey is the deterministic OSDistributionTarget key from §4.1.1:
// `{distro_family}|{version}|{architecture}`. No fuzzy matching.
func (t Target) NaturalKey() string {
	return t.DistroFamily + "|" + t.Version + "|" + t.Architecture
}

// Pinned reports whether this target names an explicit image digest.
func (t Target) Pinned() bool {
	return digestPattern.MatchString(t.ImageDigest)
}

// PinnedRef is the image reference the matrix actually boots. When a digest
// is pinned the tag is dropped entirely, so what runs is byte-identical to
// what was reviewed; an unpinned target falls back to the floating tag and
// is reported as a base_image_digest_drift finding by the checks.
func (t Target) PinnedRef() string {
	if !t.Pinned() {
		return t.BaseImageRef
	}
	repo := t.BaseImageRef
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	return repo + "@" + t.ImageDigest
}

// Tag returns the floating tag portion of BaseImageRef ("22.04", "devel"),
// which is what the scheduled drift-check re-resolves against the registry.
func (t Target) Tag() string {
	if i := strings.LastIndex(t.BaseImageRef, ":"); i > strings.LastIndex(t.BaseImageRef, "/") {
		return t.BaseImageRef[i+1:]
	}
	return "latest"
}

// Repository returns the registry repository path ("docker.io/library/ubuntu").
func (t Target) Repository() string {
	if i := strings.LastIndex(t.BaseImageRef, ":"); i > strings.LastIndex(t.BaseImageRef, "/") {
		return t.BaseImageRef[:i]
	}
	return t.BaseImageRef
}

// Validate checks the structural invariants a target must always satisfy.
//
// Note what is deliberately *not* checked here: whether a blocking target is
// digest-pinned. That rule is RequirePin, enforced only when the leg actually
// runs, so the fast untagged unit suite stays green while an unpinned leg
// still fails loudly in CI.
func (t Target) Validate() error {
	switch {
	case t.Slug == "":
		return errors.New("target: slug is required")
	case t.DistroFamily == "":
		return fmt.Errorf("target %s: distro_family is required", t.Slug)
	case t.Version == "":
		return fmt.Errorf("target %s: version is required", t.Slug)
	case t.Architecture == "":
		return fmt.Errorf("target %s: architecture is required", t.Slug)
	case t.BaseImageRef == "":
		return fmt.Errorf("target %s: base_image_ref is required", t.Slug)
	case t.SeedScript == "":
		return fmt.Errorf("target %s: seed_script is required", t.Slug)
	case t.ExpectedFile == "":
		return fmt.Errorf("target %s: expected_file is required", t.Slug)
	case !validSupportStatus[t.SupportStatus]:
		return fmt.Errorf(
			"target %s: support_status %q is outside the closed enum",
			t.Slug, t.SupportStatus,
		)
	case t.ImageDigest != "" && !t.Pinned():
		return fmt.Errorf(
			"target %s: image_digest %q is not a sha256:<64 hex> digest",
			t.Slug, t.ImageDigest,
		)
	}
	// §4.2.1 axiom: an EOL or interim target must never silently become
	// PR-blocking. Blocking is only ever valid for a supported LTS.
	if t.Blocking && (!t.IsLTS || t.SupportStatus != SupportActive) {
		return fmt.Errorf(
			"target %s: blocking requires is_lts=true and support_status=%q (got is_lts=%t, %q)",
			t.Slug, SupportActive, t.IsLTS, t.SupportStatus,
		)
	}
	return nil
}

// RequirePin enforces R3 at run time: a leg that can block a merge must name
// the exact image bytes it was reviewed against. Returns an actionable error
// rather than silently testing against whatever the tag resolves to today.
func (t Target) RequirePin() error {
	if !t.Blocking || t.Pinned() {
		return nil
	}
	return fmt.Errorf(
		"target %s is blocking but has no pinned image_digest; "+
			"run `make pin-ubuntu-matrix` and commit the updated targets.json",
		t.Slug,
	)
}

// Policy is the DistributionSupportPolicy (§4.1.5) — the human-owned record
// of which Ubuntu versions the matrix commits to, and why.
type Policy struct {
	PolicyName            string `json:"policy_name"`
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	LastReviewedAt        string `json:"last_reviewed_at"`
	MinLTSVersionsCovered int    `json:"min_lts_versions_covered"`
	ReviewCadenceDays     int    `json:"review_cadence_days"`
	IncludeLatestInterim  bool   `json:"include_latest_interim"`
}

// NaturalKey is `{vendor}|{product}|{policy_name}` per §4.1.5.
func (p Policy) NaturalKey() string {
	return p.Vendor + "|" + p.Product + "|" + p.PolicyName
}

// Matrix is the whole declared coverage commitment: one policy plus the
// targets it governs.
type Matrix struct {
	Policy  Policy   `json:"policy"`
	Targets []Target `json:"targets"`
}

// Validate enforces the matrix-level invariants, including the R4 check that
// declared coverage actually satisfies the policy rather than drifting from
// it silently.
func (m Matrix) Validate() error {
	if len(m.Targets) == 0 {
		return errors.New("matrix: no targets declared")
	}
	if m.Policy.MinLTSVersionsCovered < 2 {
		return fmt.Errorf(
			"matrix: policy min_lts_versions_covered=%d, must be >= 2 "+
				"(Canonical overlaps two LTS standard-support windows)",
			m.Policy.MinLTSVersionsCovered,
		)
	}

	seen := make(map[string]string, len(m.Targets))
	activeLTS, interim := 0, 0
	for _, t := range m.Targets {
		if err := t.Validate(); err != nil {
			return err
		}
		if prev, dup := seen[t.NaturalKey()]; dup {
			return fmt.Errorf(
				"matrix: targets %s and %s share natural key %s",
				prev, t.Slug, t.NaturalKey(),
			)
		}
		seen[t.NaturalKey()] = t.Slug
		if t.IsLTS && t.SupportStatus == SupportActive {
			activeLTS++
		}
		if t.SupportStatus == SupportInterim {
			interim++
		}
	}

	if activeLTS < m.Policy.MinLTSVersionsCovered {
		return fmt.Errorf(
			"matrix: policy requires %d supported LTS targets, only %d declared "+
				"active — re-check membership against software_lifecycle "+
				"(vendor=%s, product=%s)",
			m.Policy.MinLTSVersionsCovered, activeLTS,
			m.Policy.Vendor, m.Policy.Product,
		)
	}
	if m.Policy.IncludeLatestInterim && interim == 0 {
		return errors.New(
			"matrix: policy sets include_latest_interim but no interim target is declared",
		)
	}
	return nil
}

// Target looks a target up by slug.
func (m Matrix) Target(slug string) (Target, bool) {
	for _, t := range m.Targets {
		if t.Slug == slug {
			return t, true
		}
	}
	return Target{}, false
}

// Slugs returns every declared target slug, sorted for stable output.
func (m Matrix) Slugs() []string {
	out := make([]string, 0, len(m.Targets))
	for _, t := range m.Targets {
		out = append(out, t.Slug)
	}
	sort.Strings(out)
	return out
}

// Dir resolves this suite's directory from the compiled-in source path, so
// fixture lookups do not depend on the caller's working directory.
func Dir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

// RepoRoot is the kite-collector module root (three levels up from this
// suite: tests/e2e/ubuntu-matrix).
func RepoRoot() string {
	return filepath.Clean(filepath.Join(Dir(), "..", "..", ".."))
}

// Path joins a suite-relative path (as stored in targets.json) onto Dir().
func Path(rel string) string {
	return filepath.Join(Dir(), filepath.FromSlash(rel))
}

// LoadMatrix reads and validates targets.json.
func LoadMatrix() (Matrix, error) {
	return LoadMatrixFile(Path("targets.json"))
}

// LoadMatrixFile reads and validates a matrix declaration from an explicit
// path. Split from LoadMatrix so tests can exercise malformed inputs.
func LoadMatrixFile(path string) (Matrix, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- suite-local, non-user-supplied fixture path
	if err != nil {
		return Matrix{}, fmt.Errorf("read matrix %s: %w", path, err)
	}
	var m Matrix
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Matrix{}, fmt.Errorf("parse matrix %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return Matrix{}, err
	}
	return m, nil
}
