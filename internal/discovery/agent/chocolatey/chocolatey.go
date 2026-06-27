// Package chocolatey inventories Chocolatey-installed Windows
// packages by walking the on-disk metadata at
// C:\ProgramData\chocolatey\lib\<pkg>\<pkg>.nuspec. Each .nuspec is
// a small XML document NuGet defines for package descriptors; we
// extract the security-relevant fields and feed them to the audit
// pipeline's CVE-correlation step.
//
// File-based discovery is the deliberate choice — every Chocolatey
// install writes these files at a predictable path, and the audit
// pipeline can hash them for drift detection without spinning up
// `choco list` (slow) or hitting the registry (different surface).
//
// Headline finding shapes (MITRE T1195 — Supply Chain Compromise,
// defender side):
//
//   - `has_no_license_metadata=1` — packages without a declared
//     license raise compliance flags and indicate either private
//     internal feeds or hand-rolled packages.
//   - `is_from_non_default_source=1` — packages installed from
//     custom NuGet feeds (anything other than the official
//     community.chocolatey.org gallery) widen the supply-chain
//     attack surface; an attacker who compromises the feed
//     installs malware on every upgrade.
//   - `is_prerelease=1` — pre-release SemVer markers (`-beta`,
//     `-rc`, `-dev`) in the version string. These packages skip
//     part of the gallery's signing review.
//
// Read-only by intent — we walk the metadata directory only,
// never invoke `choco`. (Project guideline 4.2.)
package chocolatey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// MaxPackages bounds per-scan output. A typical dev workstation has
// 30-150 chocolatey packages; the 4096 ceiling covers heavily-
// customised build farms without bloating SQLite writes.
const MaxPackages = 4096

// DefaultGallerySource is the official Chocolatey community feed.
// Anything else flags is_from_non_default_source.
const DefaultGallerySource = "https://community.chocolatey.org/api/v2/"

// Package mirrors host_chocolatey_packages' column shape exactly.
type Package struct {
	FilePath               string       `json:"file_path"`
	FileHash               string       `json:"file_hash"`
	PackageID              string       `json:"package_id"`
	PackageVersion         string       `json:"package_version"`
	Title                  string       `json:"title,omitempty"`
	Authors                string       `json:"authors,omitempty"`
	Owners                 string       `json:"owners,omitempty"`
	ProjectURL             string       `json:"project_url,omitempty"`
	LicenseURL             string       `json:"license_url,omitempty"`
	LicenseExpression      string       `json:"license_expression,omitempty"`
	Description            string       `json:"description,omitempty"`
	Summary                string       `json:"summary,omitempty"`
	Tags                   string       `json:"tags,omitempty"`
	ReleaseNotes           string       `json:"release_notes,omitempty"`
	SourceURL              string       `json:"source_url,omitempty"`
	Dependencies           []Dependency `json:"dependencies,omitempty"`
	DependencyCount        int          `json:"dependency_count,omitempty"`
	HasNoLicenseMetadata   bool         `json:"has_no_license_metadata"`
	IsFromNonDefaultSource bool         `json:"is_from_non_default_source"`
	IsPrerelease           bool         `json:"is_prerelease"`
}

// Dependency mirrors one <dependency> element. Chocolatey allows
// floating versions (`[2.0,)`); we keep them as strings for the
// audit pipeline to interpret.
type Dependency struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Package, error)
}

// HashContents returns the SHA-256 hex of a nuspec body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IsPrereleaseVersion reports whether a SemVer string carries a
// pre-release marker (`-beta`, `-rc.1`, `-dev`, …). Chocolatey
// follows NuGet's strict SemVer subset: a `-` after the patch
// component begins the pre-release identifier.
func IsPrereleaseVersion(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	// Strip any leading `v`.
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// `+` marks build metadata, which we ignore.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return strings.IndexByte(v, '-') >= 0
}

// IsFromNonDefaultSource reports whether a source URL is anything
// other than the official Chocolatey community feed. Empty source
// (which can mean "unknown" or "manually installed") returns false
// — the audit pipeline gets a `source_url=”` row and decides.
func IsFromNonDefaultSource(source string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	if s == "" {
		return false
	}
	return !strings.HasPrefix(s, "https://community.chocolatey.org/") &&
		!strings.HasPrefix(s, "https://chocolatey.org/") &&
		!strings.HasPrefix(s, "https://push.chocolatey.org/")
}

// AnnotateSecurity sets the derived booleans on a Package that has
// its raw fields populated.
func AnnotateSecurity(p *Package) {
	p.HasNoLicenseMetadata = strings.TrimSpace(p.LicenseURL) == "" &&
		strings.TrimSpace(p.LicenseExpression) == ""
	p.IsFromNonDefaultSource = IsFromNonDefaultSource(p.SourceURL)
	p.IsPrerelease = IsPrereleaseVersion(p.PackageVersion)
	p.DependencyCount = len(p.Dependencies)
}

// SortPackages returns a deterministic ordering by package_id, then
// version.
func SortPackages(ps []Package) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].PackageID != ps[j].PackageID {
			return ps[i].PackageID < ps[j].PackageID
		}
		return ps[i].PackageVersion < ps[j].PackageVersion
	})
}

// EncodeDependencies returns the canonical JSON shape for the
// dependencies_json column. Empty input always emits "[]".
func EncodeDependencies(ds []Dependency) string {
	if len(ds) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ds)
	if err != nil {
		return "[]"
	}
	return string(b)
}
