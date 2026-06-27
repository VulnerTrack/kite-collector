// Package winawscreds audits AWS credentials + config profile
// files across Windows, Linux, and macOS. AWS access keys are
// long-lived; a single readable `~/.aws/credentials` with
// `aws_access_key_id` + `aws_secret_access_key` set is full
// cloud-account compromise material on most orgs.
//
// File-based discovery is the deliberate design choice. The AWS
// CLI walks the same files (plus `AWS_SHARED_CREDENTIALS_FILE` /
// `AWS_CONFIG_FILE` env vars), so anything the CLI can use, this
// collector inventories. Drift is captured via SHA-256 of the
// file body — credential rotations / additions / removals all
// surface as hash changes.
//
// Headline finding shapes (MITRE T1552.001 — Credentials in
// Files, T1078.004 — Cloud Accounts):
//
//   - `is_credential_exposure_risk=1` — rolled-up alert: any
//     profile with a static access key in a file that's
//     world-or-group-readable, OR a role-assumption profile
//     without MFA.
//   - `has_access_key=1` — the file declares
//     `aws_access_key_id`. Combined with `is_world_readable`
//     = immediate incident.
//   - `has_session_token=1` — session credentials present. Less
//     urgent because the secret expires within hours, but the
//     access key ID itself still leaks.
//   - `has_role_arn=1` + `has_mfa_serial=0` — role assumption
//     without MFA (CWE-308 single-factor on a privileged role).
//
// Read-only by intent — we walk the .aws/ directory only, never
// invoke `aws` / `aws sso login`. (Project guideline 4.2.)
package winawscreds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxProfiles bounds per-scan output. A typical engineer carries
// 3-20 profiles; the 4096 ceiling covers cloud-admins with
// vendor-merged credentials across every account in the org.
const MaxProfiles = 4096

// FileKind tags which AWS config file the row came from. Pinned
// to the host_aws_profiles.file_kind CHECK enum.
type FileKind string

const (
	FileCredentials FileKind = "credentials"
	FileConfig      FileKind = "config"
	FileUnknown     FileKind = "unknown"
)

// Profile mirrors host_aws_profiles' column shape exactly.
type Profile struct {
	MFASerial                string   `json:"mfa_serial,omitempty"`
	ProfileName              string   `json:"profile_name"`
	FilePath                 string   `json:"file_path"`
	SSORoleName              string   `json:"sso_role_name,omitempty"`
	UserProfile              string   `json:"user_profile,omitempty"`
	FileKind                 FileKind `json:"file_kind"`
	RoleARN                  string   `json:"role_arn,omitempty"`
	AccessKeyIDFingerprint   string   `json:"access_key_id_fingerprint,omitempty"`
	Region                   string   `json:"region,omitempty"`
	Output                   string   `json:"output,omitempty"`
	FileHash                 string   `json:"file_hash"`
	SourceProfile            string   `json:"source_profile,omitempty"`
	SSOAccountID             string   `json:"sso_account_id,omitempty"`
	FileOwnerUID             int      `json:"file_owner_uid,omitempty"`
	FileMode                 int      `json:"file_mode,omitempty"`
	HasSecretAccessKey       bool     `json:"has_secret_access_key"`
	HasAccessKey             bool     `json:"has_access_key"`
	HasSessionToken          bool     `json:"has_session_token"`
	HasRoleARN               bool     `json:"has_role_arn"`
	HasMFASerial             bool     `json:"has_mfa_serial"`
	HasSSO                   bool     `json:"has_sso"`
	IsWorldReadable          bool     `json:"is_world_readable"`
	IsGroupReadable          bool     `json:"is_group_readable"`
	IsCredentialExposureRisk bool     `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Profile, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AccessKeyIDPrefix returns the first 4 characters of an AWS
// access key ID — enough to identify the AKID family (`AKIA*` =
// long-lived, `ASIA*` = session, `AGPA*` = group, `AROA*` = role)
// for the audit pipeline's correlation without persisting the
// full ID. Empty input returns "".
func AccessKeyIDPrefix(akid string) string {
	a := strings.TrimSpace(akid)
	if len(a) < 4 {
		return ""
	}
	return strings.ToUpper(a[:4])
}

// AnnotateSecurity sets the derived booleans on a Profile that
// has its raw fields populated. The caller must set FileMode +
// FileOwnerUID before calling.
func AnnotateSecurity(p *Profile) {
	if p.FileMode != 0 {
		p.IsWorldReadable = p.FileMode&0o004 != 0
		p.IsGroupReadable = p.FileMode&0o040 != 0
	}
	// Headline rollup: a static access key in a readable file =
	// immediate incident. A role-assumption profile without MFA =
	// audit-worthy. Either condition triggers.
	staticInReadableFile := p.HasAccessKey && (p.IsWorldReadable || p.IsGroupReadable)
	roleWithoutMFA := p.HasRoleARN && !p.HasMFASerial
	p.IsCredentialExposureRisk = staticInReadableFile || roleWithoutMFA
}

// SortProfiles returns a deterministic ordering by file path
// then profile name.
func SortProfiles(ps []Profile) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].FilePath != ps[j].FilePath {
			return ps[i].FilePath < ps[j].FilePath
		}
		return ps[i].ProfileName < ps[j].ProfileName
	})
}
