// Package linuxdpkginventory audits Debian/Ubuntu dpkg + apt
// artifacts cached on Linux workstations. Closes the cross-
// OS triad (Windows iters 121-126, macOS iter 127) by
// adding the Linux-native software-licence inventory layer.
//
// /var/lib/dpkg/status is the canonical Debian inventory:
// one RFC-822-style stanza per installed package carrying
// Package, Maintainer, Version, Description, Homepage — the
// fields ISO/IEC 27001:2022 A.5.32 requires.
//
// **Distinct from**:
//   - iter 121 winsoftwarelicences  per-licence file (any OS)
//   - iter 122 winsamexports        SAM-tool exports
//   - iter 123 winregistryuninstall Windows Uninstall
//   - iter 124 winsbom              SBOM artifacts
//   - iter 125 winchocolatey        Chocolatey nuspec
//   - iter 126 winwingetexport      winget exports
//   - iter 127 macosinfoplist       macOS Info.plist
//
// Headline finding shapes:
//
//   - `has_pii_packages=1` — packages match the catalogue.
//   - `has_dev_packages=1` — > 0 -dev / -headers packages
//     (developer host).
//   - `has_third_party_repos=1` — > 0 packages with non-
//     Debian maintainer (PPA / corporate — supply-chain
//     surface).
//   - `has_recent_install=1` — apt history shows install
//     within 30d.
//   - `is_credential_exposure_risk=1` — readable file +
//     packages > 0 + (PII OR third-party-repos).
//
// Read-only by intent. (Project guideline 4.2.)
package linuxdpkginventory

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

// MaxFileBytes bounds per-file read (64 MiB — dpkg status
// for a desktop workstation can exceed 10 MiB and apt
// history.log accumulates over months).
const MaxFileBytes = 64 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// RecentInstallWindow — install event within this triggers
// has_recent_install.
const RecentInstallWindow = 30 * 24 * time.Hour

// ArtifactKind pinned to host_linux_dpkg_inventory.artifact_kind.
type ArtifactKind string

const (
	KindDpkgStatus     ArtifactKind = "dpkg-status"
	KindDpkgCopyright  ArtifactKind = "dpkg-copyright"
	KindDpkgList       ArtifactKind = "dpkg-list"
	KindAptHistoryLog  ArtifactKind = "apt-history-log"
	KindAptTermLog     ArtifactKind = "apt-term-log"
	KindDpkgLog        ArtifactKind = "dpkg-log"
	KindDebPackageList ArtifactKind = "deb-package-list"
	KindOther          ArtifactKind = "other"
	KindUnknown        ArtifactKind = "unknown"
)

// Row mirrors host_linux_dpkg_inventory' column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	LatestInstallYYYYMMDD     string       `json:"latest_install_yyyymmdd,omitempty"`
	EarliestInstallYYYYMMDD   string       `json:"earliest_install_yyyymmdd,omitempty"`
	PackageCount              int64        `json:"package_count,omitempty"`
	DebianMaintainerCount     int64        `json:"debian_maintainer_count,omitempty"`
	ThirdPartyMaintainerCount int64        `json:"third_party_maintainer_count,omitempty"`
	PIIPackageCount           int64        `json:"pii_package_count,omitempty"`
	DevPackageCount           int64        `json:"dev_package_count,omitempty"`
	InstallEventCount         int64        `json:"install_event_count,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasPIIPackages            bool         `json:"has_pii_packages"`
	HasDevPackages            bool         `json:"has_dev_packages"`
	HasThirdPartyRepos        bool         `json:"has_third_party_repos"`
	HasRecentInstall          bool         `json:"has_recent_install"`
	IsRecent                  bool         `json:"is_recent"`
	IsWorldReadable           bool         `json:"is_world_readable"`
	IsGroupReadable           bool         `json:"is_group_readable"`
	IsCredentialExposureRisk  bool         `json:"is_credential_exposure_risk"`
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
		"/var/lib/dpkg",
		"/var/log/apt",
		"/var/log",
		"/var/cache/apt",
		// Cross-OS fallback when exports land on shared mounts.
		`C:\Linux\dpkg`,
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

// UserDpkgDirs is the curated per-user relative path set
// (admins often dump dpkg state to Documents).
func UserDpkgDirs() [][]string {
	return [][]string{
		{"Documents", "dpkg"},
		{"Documents", "Inventory", "linux"},
		{".local", "share", "dpkg"},
	}
}

// IsCandidateExt reports whether the extension carries a
// dpkg / apt artifact. Many of these files are extensionless
// or use .log / .list / .copyright endings.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".log", ".list", ".copyright", ".md5sums",
		".gz", ".1", ".2", "":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the dpkg / apt catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	// Bare canonical filenames.
	switch n {
	case "status", "history.log", "term.log", "dpkg.log":
		return true
	}
	// Suffix patterns.
	if strings.HasSuffix(n, ".copyright") ||
		strings.HasSuffix(n, ".list") ||
		strings.HasSuffix(n, ".md5sums") {
		return true
	}
	// Rotated apt/dpkg logs.
	if strings.HasPrefix(n, "history.log.") ||
		strings.HasPrefix(n, "term.log.") ||
		strings.HasPrefix(n, "dpkg.log.") {
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
	case base == "status" && strings.Contains(lower, "/var/lib/dpkg"):
		return KindDpkgStatus
	case base == "status":
		// File named "status" outside the canonical path —
		// still likely a dpkg dump.
		return KindDpkgStatus
	case strings.HasSuffix(base, ".copyright"):
		return KindDpkgCopyright
	case strings.HasSuffix(base, ".list") &&
		strings.Contains(lower, "/var/lib/dpkg"):
		return KindDpkgList
	case base == "history.log" || strings.HasPrefix(base, "history.log."):
		return KindAptHistoryLog
	case base == "term.log" || strings.HasPrefix(base, "term.log."):
		return KindAptTermLog
	case base == "dpkg.log" || strings.HasPrefix(base, "dpkg.log."):
		return KindDpkgLog
	case strings.HasSuffix(base, ".list"):
		return KindDebPackageList
	}
	return KindOther
}

// pkgStanzaRE matches the start of a dpkg-status package
// stanza — the line `Package: <name>`. Each match = one
// installed package.
var pkgStanzaRE = regexp.MustCompile(`(?m)^Package:\s*(\S+)`)

// CountPackages returns the number of `Package:` headers in
// a dpkg-status body.
func CountPackages(body []byte) int64 {
	return int64(len(pkgStanzaRE.FindAllIndex(body, -1)))
}

// maintainerRE captures the `Maintainer:` line.
var maintainerRE = regexp.MustCompile(`(?m)^Maintainer:\s*(.+)$`)

// MaintainerSplit counts how many `Maintainer:` lines reference
// a debian.org domain (or @lists.debian.org / @lists.ubuntu.com)
// vs everything else. The Debian / Ubuntu official maintainers
// are trusted upstream; anything else is third-party
// (PPAs, corporate APT repos, manually-installed .deb files).
func MaintainerSplit(body []byte) (debian, thirdParty int64) {
	matches := maintainerRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		maint := strings.ToLower(m[1])
		switch {
		case strings.Contains(maint, "debian.org"),
			strings.Contains(maint, "ubuntu.com"),
			strings.Contains(maint, "@lists.debian"),
			strings.Contains(maint, "@lists.ubuntu"):
			debian++
		default:
			thirdParty++
		}
	}
	return debian, thirdParty
}

// PIIPackageMarkers — lowercased package-name fingerprints
// that flag PII / financial / PHI handling. Shared concept
// with iters 121-127.
func PIIPackageMarkers() []string {
	return []string{
		// Browsers (cookies + credentials)
		"firefox", "firefox-esr", "chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable", "microsoft-edge",
		"brave-browser",
		// Email
		"thunderbird", "evolution", "claws-mail", "mutt",
		// Office / productivity
		"libreoffice", "libreoffice-core", "libreoffice-impress",
		// Databases (PII storage)
		"postgresql", "mariadb-server", "mysql-server", "redis-server",
		"mongodb", "couchdb",
		// Collaboration / chat
		"slack", "slack-desktop", "zoom", "teams-for-linux",
		"signal-desktop", "telegram-desktop",
		// Accounting / financial (rare on Linux but track)
		"gnucash", "homebank", "moneydance",
		// Dev tools that handle credentials
		"git", "openssh-client", "openssh-server", "vault",
	}
}

// CountPIIPackages walks `Package:` lines and counts how many
// match the PII catalogue.
func CountPIIPackages(body []byte) int64 {
	matches := pkgStanzaRE.FindAllStringSubmatch(string(body), -1)
	markers := PIIPackageMarkers()
	var count int64
	for _, m := range matches {
		pkg := strings.ToLower(m[1])
		for _, marker := range markers {
			if pkg == marker {
				count++
				break
			}
		}
	}
	return count
}

// CountDevPackages walks `Package:` lines and counts -dev /
// -headers / -devel / -static suffixed packages. Linux kernel
// header packages typically embed an arch suffix
// (`linux-headers-amd64`, `linux-headers-generic`) so the
// `-headers` check uses Contains rather than HasSuffix.
func CountDevPackages(body []byte) int64 {
	matches := pkgStanzaRE.FindAllStringSubmatch(string(body), -1)
	var count int64
	for _, m := range matches {
		pkg := strings.ToLower(m[1])
		switch {
		case strings.HasSuffix(pkg, "-dev"),
			strings.HasSuffix(pkg, "-devel"),
			strings.HasSuffix(pkg, "-static"):
			count++
		case strings.Contains(pkg, "-headers"):
			count++
		}
	}
	return count
}

// historyInstallRE captures Start-Date and Install lines in
// apt history.log:
//
//	Start-Date: 2026-06-15  10:30:45
var historyDateRE = regexp.MustCompile(`(?m)^Start-Date:\s+(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))`)

// historyInstallActionRE counts only Install: lines (vs
// Upgrade:/Remove:/Purge:).
var historyInstallActionRE = regexp.MustCompile(`(?m)^Install:\s+`)

// AptInstallStats walks an apt history.log body and returns
// (count_of_install_events, earliest_date, latest_date) as
// YYYYMMDD strings. Dates are derived from Start-Date markers
// that precede each install event.
func AptInstallStats(body []byte) (events int64, earliest, latest string) {
	dates := historyDateRE.FindAllStringSubmatch(string(body), -1)
	installs := int64(len(historyInstallActionRE.FindAllIndex(body, -1)))
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
	if r.ThirdPartyMaintainerCount > 0 {
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
	if hasReadable && r.PackageCount > 0 && hasRisk {
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
