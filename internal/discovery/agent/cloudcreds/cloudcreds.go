// Package cloudcreds enumerates cloud-provider credential files across
// every user home directory: AWS (~/.aws/), GCP (~/.config/gcloud/),
// Kubernetes (~/.kube/config), and stubs for Azure / GitHub / Docker /
// npm / Terraform Cloud. The schema is normalised across providers so a
// single CWE-1004 / T1552.001 audit query catches stale credentials
// regardless of which cloud they belong to.
//
// PRIVACY + SECURITY INVARIANT (enforced by every parser):
//   - NEVER load secret material into memory beyond what's needed to
//     decide structural questions (is this an encrypted file? does it
//     contain a session token?).
//   - NEVER persist secret material. Only NON-SECRET identifiers
//     (AWS account IDs, access-key IDs, GCP project IDs, k8s server
//     URLs) are stored.
//   - The collector reads private key material exactly twice — once
//     during the file walk to decide structural booleans (e.g.
//     `session_token_present`), and once to scan for the AKIA prefix.
//     The bytes are then dropped without being passed to slog / written
//     anywhere.
//
// Every collector is **read-only** — it never edits credential files,
// rotates keys, or invokes provider APIs.
//
// Credential rows feed the audit pipeline:
//
//   - T1552.001 (Unsecured Credentials in Files) — every row in this
//     table is a candidate finding. `is_long_lived=1` rows are the
//     anti-pattern.
//   - CWE-308 (Single-Factor Authentication for Critical Function) —
//     `has_mfa=0 AND is_long_lived=1` on a cloud control plane is a
//     finding.
//   - Cross-host duplicate detection — same `key_id` across multiple
//     hosts indicates a shared credential (policy violation in AWS
//     IAM, GCP IAM, Azure RBAC).
package cloudcreds

import (
	"context"
	"sort"
	"strings"
)

// MaxCredentials bounds per-scan output. A typical dev laptop has 1-3
// cloud providers × maybe 5 profiles + 5-20 kubeconfig contexts. The
// 1024 ceiling protects the SQLite write path.
const MaxCredentials = 1024

// Provider classifies the cloud / registry / package-repo. Strings
// pinned to host_cloud_credentials.provider CHECK enum.
type Provider string

const (
	ProviderAWS            Provider = "aws"
	ProviderGCP            Provider = "gcp"
	ProviderAzure          Provider = "azure"
	ProviderKubernetes     Provider = "kubernetes"
	ProviderKubeconfig     Provider = "kubeconfig"
	ProviderGitHub         Provider = "github"
	ProviderGitLab         Provider = "gitlab"
	ProviderBitbucket      Provider = "bitbucket"
	ProviderDocker         Provider = "docker"
	ProviderHelm           Provider = "helm"
	ProviderNPM            Provider = "npm"
	ProviderPyPI           Provider = "pypi"
	ProviderTerraformCloud Provider = "terraform-cloud"
	ProviderVault          Provider = "hashicorp-vault"
	ProviderCloudflare     Provider = "cloudflare"
	ProviderDigitalOcean   Provider = "digitalocean"
	ProviderUnknown        Provider = "unknown"
)

// CredentialType classifies the form of the credential. Pinned to
// host_cloud_credentials.credential_type CHECK enum.
type CredentialType string

const (
	CredAccessKey         CredentialType = "access-key"
	CredSessionToken      CredentialType = "session-token"
	CredServiceAccountKey CredentialType = "service-account-key"
	CredOAuthRefresh      CredentialType = "oauth-refresh-token" //#nosec G101 -- enum value, not a credential
	CredOAuthAccess       CredentialType = "oauth-access-token"  //#nosec G101 -- enum value, not a credential
	CredSSOCache          CredentialType = "sso-cache"
	CredKubeconfigContext CredentialType = "kubeconfig-context" //#nosec G101 -- enum value, not a credential
	CredBearerToken       CredentialType = "bearer-token"
	CredBasicAuth         CredentialType = "basic-auth"
	CredAPIKey            CredentialType = "api-key"
	CredUnknown           CredentialType = "unknown"
)

// SourceFormat classifies the parser used. Pinned enum.
type SourceFormat string

const (
	FormatINI     SourceFormat = "ini"
	FormatJSON    SourceFormat = "json"
	FormatYAML    SourceFormat = "yaml"
	FormatUnknown SourceFormat = "unknown"
)

// Credential is the cross-provider record produced by every collector.
// Mirrors host_cloud_credentials' column shape exactly.
type Credential struct {
	Provider            Provider       `json:"provider"`
	CredentialType      CredentialType `json:"credential_type"`
	Profile             string         `json:"profile"`
	OwnerUser           string         `json:"owner_user,omitempty"`
	AccountID           string         `json:"account_id,omitempty"`
	Region              string         `json:"region,omitempty"`
	KeyID               string         `json:"key_id,omitempty"`
	RoleARN             string         `json:"role_arn,omitempty"`
	FederatedVia        string         `json:"federated_via,omitempty"`
	ExpiresAt           string         `json:"expires_at,omitempty"`
	SourcePath          string         `json:"source_path"`
	SourceFormat        SourceFormat   `json:"source_format"`
	IsLongLived         bool           `json:"is_long_lived"`
	SessionTokenPresent bool           `json:"session_token_present"`
	HasMFA              bool           `json:"has_mfa"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Credential, error)
}

// IsLikelyAWSAccessKeyID reports whether s matches AWS's documented
// access-key-ID format: starts with AKIA (long-lived) / ASIA (session) /
// AGPA / AIDA (other IAM principals), 20 chars, base32-ish. The check
// is intentionally loose — false positives are noise, false negatives
// are the catastrophe.
func IsLikelyAWSAccessKeyID(s string) bool {
	if len(s) != 20 {
		return false
	}
	switch s[:4] {
	case "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA":
	default:
		return false
	}
	for i := 4; i < 20; i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// IsLongLivedAWSPrefix reports whether the access-key ID prefix
// represents a long-lived (non-temporary) credential. AWS:
//
//	AKIA = long-lived IAM access key
//	ASIA = short-lived STS session token
//	AROA, AIDA, etc. = other principal types (not access-key-style)
func IsLongLivedAWSPrefix(keyID string) bool {
	return strings.HasPrefix(keyID, "AKIA")
}

// SortCredentials returns a deterministic ordering: provider, source
// path, profile.
func SortCredentials(cs []Credential) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Provider != cs[j].Provider {
			return cs[i].Provider < cs[j].Provider
		}
		if cs[i].SourcePath != cs[j].SourcePath {
			return cs[i].SourcePath < cs[j].SourcePath
		}
		return cs[i].Profile < cs[j].Profile
	})
}
