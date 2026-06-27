// Package winsysmon inventories the on-disk Sysmon configuration
// XML. Sysmon is the de-facto Windows endpoint telemetry engine; its
// per-event coverage is entirely driven by the XML loaded with
// `Sysmon -c <file.xml>`. The same file then sits at one of a
// handful of canonical paths the audit pipeline can hash.
//
// File-based discovery is the deliberate design choice — every
// Sysmon install writes its config to disk, and the audit pipeline
// can detect drift without spawning Sysmon-CLI.
//
// Headline finding shapes (MITRE T1562.001 — Disable or Modify
// Tools, T1564.005 — Hidden File System/Process):
//
//   - `has_no_process_create_rules` — ProcessCreate RuleGroup
//     missing; EventID 1 (the most useful telemetry) is off.
//   - `has_no_network_connect_rules` — EventID 3 off; C2
//     callbacks invisible.
//   - `has_no_dns_query_rules` — EventID 22 off; DNS beacons
//     invisible.
//   - `has_suspicious_exclusion` — exclusion entry matches a
//     world-writable path (Public, Temp, …). Common implant
//     pattern: ship the dropper alongside an XML patch that
//     excludes its install path.
//   - `is_schema_outdated` — schemaversion < 4.50; pre-4.50
//     lacks FileBlockExecutable / ProcessTampering coverage.
//
// Read-only by intent — we parse the file only, never invoke
// `Sysmon.exe` or service control. (Project guideline 4.2.)
package winsysmon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MinSchemaVersion is the floor we consider safe for `schemaversion`.
// Anything below 4.50 lacks the FileBlockExecutable /
// ProcessTampering coverage shipped in 2021.
const MinSchemaVersion = 4.50

// Source identifies which probe path produced the row. Pinned to
// the host_sysmon_config.source CHECK enum.
type Source string

const (
	SourceConfigXML Source = "config-xml"
	SourceNoConfig  Source = "no-config"
	SourceNoProbe   Source = "no-probe"
	SourceUnknown   Source = "unknown"
)

// State mirrors host_sysmon_config's column shape exactly.
type State struct {
	ConfigPath               string   `json:"config_path,omitempty"`
	FileHash                 string   `json:"file_hash,omitempty"`
	SchemaVersion            string   `json:"schema_version,omitempty"`
	HashAlgorithms           string   `json:"hash_algorithms,omitempty"`
	Source                   Source   `json:"source"`
	ArchiveDirectory         string   `json:"archive_directory,omitempty"`
	RuleGroups               []string `json:"rule_groups,omitempty"`
	ExclusionImagePaths      []string `json:"exclusion_image_paths,omitempty"`
	SuspiciousExclusionPaths []string `json:"suspicious_exclusion_paths,omitempty"`
	RuleGroupCount           int      `json:"rule_group_count"`
	ExclusionCount           int      `json:"exclusion_count"`
	DNSLookupEnabled         bool     `json:"dns_lookup_enabled"`
	CheckRevocationEnabled   bool     `json:"check_revocation_enabled"`
	IsSchemaOutdated         bool     `json:"is_schema_outdated"`
	HasStrongHashAlgorithms  bool     `json:"has_strong_hash_algorithms"`
	HasNoProcessCreateRules  bool     `json:"has_no_process_create_rules"`
	HasNoNetworkConnectRules bool     `json:"has_no_network_connect_rules"`
	HasNoDNSQueryRules       bool     `json:"has_no_dns_query_rules"`
	HasSuspiciousExclusion   bool     `json:"has_suspicious_exclusion"`
	IsHardened               bool     `json:"is_hardened"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (State, error)
}

// HashContents returns the SHA-256 hex of a config-file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WorldWritableDirRoots is the curated set of directory prefixes
// any local user can write into. Sysmon exclusions matching these
// surface the suspicious-exclusion finding.
func WorldWritableDirRoots() []string {
	return []string{
		`c:\users\public\`,
		`c:\windows\temp\`,
		`c:\temp\`,
		`c:\programdata\temp\`,
		`%temp%\`,
		`%tmp%\`,
		`%public%\`,
		`%userprofile%\appdata\local\temp\`,
	}
}

// IsSuspiciousExclusionPath reports whether an exclusion entry
// names a path under one of the curated world-writable roots.
// Comparison is case-insensitive (Windows paths are case-insensitive
// by definition).
func IsSuspiciousExclusionPath(path string) bool {
	v := strings.ToLower(strings.TrimSpace(path))
	if v == "" {
		return false
	}
	v = strings.Trim(v, `"`)
	cleaned := filepath.ToSlash(v)
	for _, root := range WorldWritableDirRoots() {
		r := filepath.ToSlash(root)
		if strings.HasPrefix(cleaned, r) {
			return true
		}
	}
	return false
}

// FilterSuspiciousExclusions returns the subset of paths that match
// the suspicious-roots set. Order preserved.
func FilterSuspiciousExclusions(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if IsSuspiciousExclusionPath(p) {
			out = append(out, p)
		}
	}
	return out
}

// HasStrongHashAlgorithmList reports whether the comma-separated
// algorithm list includes BOTH SHA256 AND IMPHASH — Sysmon's
// recommended baseline. Case-insensitive.
func HasStrongHashAlgorithmList(list string) bool {
	if strings.TrimSpace(list) == "" {
		return false
	}
	tokens := strings.Split(strings.ToLower(list), ",")
	hasSHA256 := false
	hasIMPHASH := false
	for _, t := range tokens {
		switch strings.TrimSpace(t) {
		case "sha256", "*":
			hasSHA256 = true
		case "imphash":
			hasIMPHASH = true
		}
	}
	return hasSHA256 && hasIMPHASH
}

// IsSchemaOutdated reports whether a schemaversion string is below
// the MinSchemaVersion floor. Empty/unparseable returns true so the
// audit pipeline flags configs without any version declared.
func IsSchemaOutdated(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return true
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return true
	}
	return f < MinSchemaVersion
}

// AnnotateSecurity sets the derived booleans on a State that has
// its raw fields populated.
func AnnotateSecurity(s *State) {
	s.IsSchemaOutdated = IsSchemaOutdated(s.SchemaVersion)
	s.HasStrongHashAlgorithms = HasStrongHashAlgorithmList(s.HashAlgorithms)
	s.RuleGroupCount = len(s.RuleGroups)
	s.ExclusionCount = len(s.ExclusionImagePaths)
	s.SuspiciousExclusionPaths = FilterSuspiciousExclusions(s.ExclusionImagePaths)
	s.HasSuspiciousExclusion = len(s.SuspiciousExclusionPaths) > 0
	s.HasNoProcessCreateRules = !containsToken(s.RuleGroups, "ProcessCreate")
	s.HasNoNetworkConnectRules = !containsToken(s.RuleGroups, "NetworkConnect")
	s.HasNoDNSQueryRules = !containsToken(s.RuleGroups, "DnsQuery")
	s.IsHardened = !s.IsSchemaOutdated &&
		s.HasStrongHashAlgorithms &&
		s.CheckRevocationEnabled &&
		!s.HasNoProcessCreateRules &&
		!s.HasNoNetworkConnectRules &&
		!s.HasNoDNSQueryRules &&
		!s.HasSuspiciousExclusion
}

func containsToken(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// SortLists normalises the string slices in place — gives the audit
// pipeline stable diffs between scans.
func SortLists(s *State) {
	sort.Strings(s.RuleGroups)
	sort.Strings(s.ExclusionImagePaths)
	sort.Strings(s.SuspiciousExclusionPaths)
}

// EncodeStringList returns a JSON array suitable for the *_json
// columns. Empty input always emits "[]" so the column is never NULL.
func EncodeStringList(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}
