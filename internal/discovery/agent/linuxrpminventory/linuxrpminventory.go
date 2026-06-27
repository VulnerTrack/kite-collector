// Package linuxrpminventory audits RPM-family Linux package
// manager artifacts cached on workstations (RHEL, Fedora,
// CentOS Stream, Rocky, Alma, openSUSE). Companion to iter
// 128 linuxdpkginventory; together they cover ~100 % of
// enterprise Linux endpoints.
//
// The most common parseable form is the rpm-qa text dump
// admins build via:
//
//	rpm -qa --queryformat \
//	  "%{NAME}|%{VERSION}|%{VENDOR}|%{URL}|%{SUMMARY}\n"
//
// Plus DNF transaction logs and .repo files for third-party
// repo detection.
//
// Complements iter 121 winsoftwarelicences (per-licence),
// iter 122 winsamexports (SAM tools), iter 123
// winregistryuninstall (Windows Uninstall), iter 124
// winsbom (SBOM artifacts), iter 125 winchocolatey
// (Chocolatey nuspec), iter 126 winwingetexport (winget
// exports), iter 127 macosinfoplist (macOS Info.plist),
// and iter 128 linuxdpkginventory (Debian dpkg).
//
// Headline finding shapes:
//
//   - `has_pii_packages=1` — packages match the catalogue.
//   - `has_dev_packages=1` — > 0 -devel suffixed packages.
//   - `has_third_party_repos=1` — > 0 vendors / repos
//     outside Red Hat / Fedora / SUSE (EPEL, Microsoft,
//     Google, Oracle, Remi, RPM Fusion — supply-chain
//     surface).
//   - `has_recent_install=1` — DNF history shows install
//     within 30d.
//   - `is_credential_exposure_risk=1` — readable file +
//     packages > 0 + (PII OR third-party-repos).
//
// Read-only by intent. (Project guideline 4.2.)
package linuxrpminventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read (64 MiB — rpm-qa for
// a desktop workstation can exceed 10 MiB; dnf.log
// accumulates over months).
const MaxFileBytes = 64 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install event within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_linux_rpm_inventory.artifact_kind.
type ArtifactKind string

const (
	KindRPMQAExport   ArtifactKind = "rpm-qa-export"
	KindDNFHistoryLog ArtifactKind = "dnf-history-log"
	KindDNFRPMLog     ArtifactKind = "dnf-rpm-log"
	KindYumLog        ArtifactKind = "yum-log"
	KindRepoConfig    ArtifactKind = "repo-config"
	KindRPMDBSQLite   ArtifactKind = "rpmdb-sqlite"
	KindRPMDBBerkeley ArtifactKind = "rpmdb-berkeley"
	KindOther         ArtifactKind = "other"
	KindUnknown       ArtifactKind = "unknown"
)

// Row mirrors host_linux_rpm_inventory' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	LatestInstallYYYYMMDD    string       `json:"latest_install_yyyymmdd,omitempty"`
	EarliestInstallYYYYMMDD  string       `json:"earliest_install_yyyymmdd,omitempty"`
	PackageCount             int64        `json:"package_count,omitempty"`
	RedHatVendorCount        int64        `json:"redhat_vendor_count,omitempty"`
	ThirdPartyVendorCount    int64        `json:"third_party_vendor_count,omitempty"`
	PIIPackageCount          int64        `json:"pii_package_count,omitempty"`
	DevPackageCount          int64        `json:"dev_package_count,omitempty"`
	RepoCount                int64        `json:"repo_count,omitempty"`
	ThirdPartyRepoCount      int64        `json:"third_party_repo_count,omitempty"`
	InstallEventCount        int64        `json:"install_event_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPIIPackages           bool         `json:"has_pii_packages"`
	HasDevPackages           bool         `json:"has_dev_packages"`
	HasThirdPartyRepos       bool         `json:"has_third_party_repos"`
	HasRecentInstall         bool         `json:"has_recent_install"`
	IsRecent                 bool         `json:"is_recent"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated install-root set.
func DefaultInstallRoots() []string {
	return []string{
		"/var/lib/rpm",
		"/var/log",
		"/etc/yum.repos.d",
		"/etc/dnf/repos.d",
		"/var/cache/dnf",
		"/var/cache/yum",
		// Cross-OS fallback for shared-mount exports.
		`C:\Linux\rpm`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		"/home",
		"/Users",
		`C:\Users`,
	}
}

// UserRPMDirs is the curated per-user relative path set.
func UserRPMDirs() [][]string {
	return [][]string{
		{"Documents", "rpm"},
		{"Documents", "Inventory", "linux"},
		{".local", "share", "rpm"},
	}
}

// IsCandidateExt reports whether the extension carries an
// RPM / DNF artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".log", ".repo", ".txt", ".sqlite", ".db",
		".1", ".2", ".gz", "":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the RPM / DNF catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	switch n {
	case "dnf.log", "dnf.rpm.log", "yum.log",
		"rpmdb.sqlite", "packages":
		return true
	}
	if strings.HasSuffix(n, ".repo") {
		return true
	}
	if strings.Contains(n, "rpm-qa") || strings.Contains(n, "rpm_qa") {
		return true
	}
	if strings.HasPrefix(n, "dnf.log.") ||
		strings.HasPrefix(n, "dnf.rpm.log.") ||
		strings.HasPrefix(n, "yum.log.") {
		return true
	}
	return false
}

// ArtifactKindFromPath classifies a file by its full path.
func ArtifactKindFromPath(path string) ArtifactKind {
	if strings.TrimSpace(path) == "" {
		return KindUnknown
	}
	normalised := strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
	lower := strings.ToLower(normalised)
	var base string
	if idx := strings.LastIndex(lower, "/"); idx >= 0 {
		base = lower[idx+1:]
	} else {
		base = lower
	}
	switch {
	case strings.Contains(base, "rpm-qa") ||
		strings.Contains(base, "rpm_qa"):
		return KindRPMQAExport
	case base == "dnf.log" || strings.HasPrefix(base, "dnf.log."):
		return KindDNFHistoryLog
	case base == "dnf.rpm.log" || strings.HasPrefix(base, "dnf.rpm.log."):
		return KindDNFRPMLog
	case base == "yum.log" || strings.HasPrefix(base, "yum.log."):
		return KindYumLog
	case strings.HasSuffix(base, ".repo"):
		return KindRepoConfig
	case base == "rpmdb.sqlite":
		return KindRPMDBSQLite
	case base == "packages" && strings.Contains(lower, "/var/lib/rpm"):
		return KindRPMDBBerkeley
	}
	return KindOther
}

// qaLineRE matches a pipe-delimited rpm-qa export line:
// NAME|VERSION|VENDOR|URL|SUMMARY. Vendor or URL can be
// empty (rendered as `(none)` by rpm). Each capture group
// excludes `|` and newline characters so empty trailing
// fields don't make the engine bleed into the next line.
var qaLineRE = regexp.MustCompile(`(?m)^([A-Za-z0-9][A-Za-z0-9_.+\-]*)\|([^|\r\n]*)\|([^|\r\n]*)\|([^|\r\n]*)\|([^|\r\n]*)$`)

// CountPackagesQA returns the number of rpm-qa pipe-delimited
// lines that look like package entries.
func CountPackagesQA(body []byte) int64 {
	return int64(len(qaLineRE.FindAllIndex(body, -1)))
}

// VendorSplit walks rpm-qa lines and classifies the VENDOR
// column into Red Hat / Fedora / SUSE official vs third-
// party. Tolerates `(none)` placeholder.
func VendorSplit(body []byte) (redhat, thirdParty int64) {
	matches := qaLineRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		vendor := strings.ToLower(strings.TrimSpace(m[3]))
		if vendor == "" || vendor == "(none)" {
			continue
		}
		switch {
		case strings.Contains(vendor, "red hat"),
			strings.Contains(vendor, "redhat"),
			strings.Contains(vendor, "fedora"),
			strings.Contains(vendor, "centos"),
			strings.Contains(vendor, "rocky"),
			strings.Contains(vendor, "almalinux"),
			strings.Contains(vendor, "suse"),
			strings.Contains(vendor, "opensuse"):
			redhat++
		default:
			thirdParty++
		}
	}
	return redhat, thirdParty
}

// PIIPackageMarkers — lowercased package-name fingerprints.
// Shared concept with iters 121-128.
func PIIPackageMarkers() []string {
	return []string{
		// Browsers
		"firefox", "firefox-esr", "chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable", "microsoft-edge",
		"brave-browser",
		// Email
		"thunderbird", "evolution", "claws-mail", "mutt",
		// Office / productivity
		"libreoffice", "libreoffice-core",
		// Databases
		"postgresql", "postgresql-server", "mariadb-server",
		"mysql-server", "redis", "mongodb-org-server",
		// Collaboration / chat
		"slack", "zoom", "teams", "signal-desktop",
		"telegram-desktop",
		// Accounting / financial
		"gnucash", "homebank",
		// Credential / SSH tools
		"openssh-clients", "openssh-server", "vault",
		"keepassxc",
	}
}

// CountPIIPackagesQA walks rpm-qa NAME columns and counts
// catalogue matches.
func CountPIIPackagesQA(body []byte) int64 {
	matches := qaLineRE.FindAllStringSubmatch(string(body), -1)
	markers := PIIPackageMarkers()
	var count int64
	for _, m := range matches {
		pkg := strings.ToLower(strings.TrimSpace(m[1]))
		for _, marker := range markers {
			if pkg == marker {
				count++
				break
			}
		}
	}
	return count
}

// CountDevPackagesQA walks rpm-qa NAME columns and counts
// -devel / -static / -headers suffixed packages.
func CountDevPackagesQA(body []byte) int64 {
	matches := qaLineRE.FindAllStringSubmatch(string(body), -1)
	var count int64
	for _, m := range matches {
		pkg := strings.ToLower(strings.TrimSpace(m[1]))
		switch {
		case strings.HasSuffix(pkg, "-devel"),
			strings.HasSuffix(pkg, "-static"):
			count++
		case strings.Contains(pkg, "-headers"):
			count++
		}
	}
	return count
}

// repoIDRE captures `[<id>]` headers in .repo files. Each
// section = one repository.
var repoIDRE = regexp.MustCompile(`(?m)^\[([A-Za-z0-9._\-]+)\]`)

// repoBaseURLRE captures `baseurl=<url>` and `mirrorlist=`
// fields inside a .repo file.
var repoBaseURLRE = regexp.MustCompile(`(?im)^(?:baseurl|metalink|mirrorlist)\s*=\s*(\S+)`)

// CountRepos returns the number of `[id]` sections in a
// .repo file body.
func CountRepos(body []byte) int64 {
	return int64(len(repoIDRE.FindAllIndex(body, -1)))
}

// CountThirdPartyRepos walks repo baseurl/mirrorlist lines
// and counts those that point to non-Red Hat / non-Fedora /
// non-SUSE / non-CentOS endpoints. EPEL counts as third-
// party even though Fedora-hosted because it's outside the
// vendor's supported channel.
func CountThirdPartyRepos(body []byte) int64 {
	matches := repoBaseURLRE.FindAllStringSubmatch(string(body), -1)
	var count int64
	for _, m := range matches {
		url := strings.ToLower(strings.TrimSpace(m[1]))
		switch {
		case strings.Contains(url, "cdn.redhat.com"),
			strings.Contains(url, "subscription.rhsm.redhat.com"),
			strings.Contains(url, "mirrors.fedoraproject.org"),
			strings.Contains(url, "download.opensuse.org"),
			strings.Contains(url, "mirrors.centos.org"),
			strings.Contains(url, "mirrors.rockylinux.org"),
			strings.Contains(url, "repo.almalinux.org"):
			// known-official.
		default:
			count++
		}
	}
	return count
}

// dnfHistoryDateRE captures `YYYY-MM-DDTHH:MM:SSZ` (ISO) and
// the older `YYYY-MM-DD HH:MM:SS` formats used by dnf.log
// transaction entries.
var dnfHistoryDateRE = regexp.MustCompile(`(?m)(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))[\sT]`)

// dnfInstallActionRE counts only "Installed:" lines.
var dnfInstallActionRE = regexp.MustCompile(`(?m)^(?:\s+|\[\d+\]\s+)?Installed:\s+`)

// DNFInstallStats walks a dnf.log body and returns
// (count_of_install_events, earliest_date, latest_date)
// as YYYYMMDD strings.
func DNFInstallStats(body []byte) (events int64, earliest, latest string) {
	dates := dnfHistoryDateRE.FindAllStringSubmatch(string(body), -1)
	installs := int64(len(dnfInstallActionRE.FindAllIndex(body, -1)))
	for _, d := range dates {
		ymd := strings.ReplaceAll(d[1], "-", "")
		if earliest == "" || ymd < earliest {
			earliest = ymd
		}
		if ymd > latest {
			latest = ymd
		}
	}
	return installs, earliest, latest
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// AnnotateSecurityWithClock is the time-injectable variant.
func AnnotateSecurityWithClock(r *Row, now func() time.Time) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.PIIPackageCount > 0 {
		r.HasPIIPackages = true
	}
	if r.DevPackageCount > 0 {
		r.HasDevPackages = true
	}
	if r.ThirdPartyVendorCount > 0 || r.ThirdPartyRepoCount > 0 {
		r.HasThirdPartyRepos = true
	}
	if r.LatestInstallYYYYMMDD != "" {
		if t, err := time.Parse("20060102", r.LatestInstallYYYYMMDD); err == nil {
			if now().Sub(t) <= RecentInstallWindow {
				r.HasRecentInstall = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasRisk := r.HasPIIPackages || r.HasThirdPartyRepos
	hasContent := r.PackageCount > 0 || r.RepoCount > 0
	if hasReadable && hasContent && hasRisk {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ArtifactKind != rs[j].ArtifactKind {
			return rs[i].ArtifactKind < rs[j].ArtifactKind
		}
		return rs[i].LatestInstallYYYYMMDD < rs[j].LatestInstallYYYYMMDD
	})
}
