// Package winafipwsaa audits Argentine AFIP/ARCA WSAA
// (Web-Service de Autenticación y Autorización) artifacts on
// Windows, Linux, and macOS billing/accounting workstations.
// Every Argentine integration that issues a `comprobante
// electrónico` carries:
//
//  1. an X.509 certificate + RSA private key issued by AFIP for
//     a specific CUIT,
//  2. a signed TRA (Ticket de Requerimiento de Acceso) the
//     client POSTs to WSAA, and
//  3. a cached TA (Ticket de Acceso) XML containing `<token>` +
//     `<sign>` valid for ~12 h.
//
// The private key gives full impersonation of the CUIT it was
// issued for (T1552.004 — Private Keys). A live cached
// `<token>` gives the holder free WSFE invoice issuance for the
// remainder of its TTL (T1552.001).
//
// File-based discovery is the deliberate design choice — every
// SDK (pyafipws, Afip.php, afipsdk-js, Tango Gestión, Bejerman,
// SIAP integrations) drops the same .crt / .key / .p12 / .pfx
// + ticket-XML shapes on disk. The audit pipeline correlates
// drift via the file SHA-256 without parsing certs repeatedly.
//
// Headline finding shapes:
//
//   - `is_private_key_unencrypted=1` — PEM key file with no
//     `ENCRYPTED PRIVATE KEY` / `Proc-Type: 4,ENCRYPTED`
//     header. Anyone who can read the file recovers the key.
//   - `is_ta_token_present=1` — cached TA contains a non-empty
//     `<token>` element. Combined with a readable file =
//     immediate incident.
//   - `is_ta_expired=1` — `<expirationTime>` is in the past.
//     Audit-only; AFIP re-issues every 12 h.
//   - `endpoint_env` — `production` / `homologation` / `unknown`,
//     based on filename + path tokens.
//   - `is_credential_exposure_risk=1` — rollup: unencrypted key
//   - readable file, OR live TA token + readable file.
//
// The CUIT is NEVER stored verbatim — only the entity-type
// prefix (20/23/24/27/30/33/34) and the last 4 digits. Tokens
// and `<sign>` values are likewise never persisted.
//
// Read-only by intent — we walk the candidate files only, never
// invoke `openssl` or call WSAA. (Project guideline 4.2.)
package winafipwsaa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxArtifacts bounds per-scan output. A typical accounting
// host carries 5-30 AFIP files; the 4096 ceiling covers
// service-bureau hosts holding certs for many CUITs.
const MaxArtifacts = 4096

// ArtifactKind tags the file's role. Pinned to the
// host_afip_wsaa_artifacts.artifact_kind CHECK enum.
type ArtifactKind string

const (
	ArtifactCert       ArtifactKind = "cert"
	ArtifactPrivateKey ArtifactKind = "private-key"
	ArtifactPKCS12     ArtifactKind = "pkcs12"
	ArtifactTAXML      ArtifactKind = "ta-xml"
	ArtifactTRACMS     ArtifactKind = "tra-cms"
	ArtifactWSAAConfig ArtifactKind = "wsaa-config"
	ArtifactUnknown    ArtifactKind = "unknown"
)

// EndpointEnv tags the target WSAA environment. Pinned to the
// host_afip_wsaa_artifacts.endpoint_env CHECK enum.
type EndpointEnv string

const (
	EndpointProduction  EndpointEnv = "production"
	EndpointHomologatio EndpointEnv = "homologation"
	EndpointUnknown     EndpointEnv = "unknown"
)

// Artifact mirrors host_afip_wsaa_artifacts' column shape.
type Artifact struct {
	CuitEntityPrefix         string       `json:"cuit_entity_prefix,omitempty"`
	FileHash                 string       `json:"file_hash"`
	TaExpiresAt              string       `json:"ta_expires_at,omitempty"`
	CuitSuffix4              string       `json:"cuit_suffix4,omitempty"`
	FilePath                 string       `json:"file_path"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	EndpointEnv              EndpointEnv  `json:"endpoint_env"`
	SubjectCN                string       `json:"subject_cn,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	IsPrivateKeyUnencrypted  bool         `json:"is_private_key_unencrypted"`
	IsTaTokenPresent         bool         `json:"is_ta_token_present"`
	IsTaExpired              bool         `json:"is_ta_expired"`
	IsWorldReadable          bool         `json:"is_world_readable"`
	IsGroupReadable          bool         `json:"is_group_readable"`
	IsCredentialExposureRisk bool         `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Artifact, error)
}

// HashContents returns the SHA-256 hex of the file body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CuitEntityPrefixes is the curated set of valid 2-digit
// AFIP/ARCA entity-type prefixes. 20/23/24/27 = persona física
// (DNI-derived); 30/33/34 = persona jurídica (CDI-derived).
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports whether `p` is one of the
// curated prefixes.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// AfipNameTokens is the curated set of filename / path tokens
// that strongly indicate AFIP / WSAA usage. Matched
// case-insensitively as a substring.
func AfipNameTokens() []string {
	return []string{
		"afip", "arca", "wsaa", "wsfe", "wsfev1", "wsmtxca",
		"pyafipws", "afipsdk", "facturador", "comprobante",
	}
}

// IsAfipPath reports whether `path` plausibly belongs to an
// AFIP integration. Matches if the basename, any directory
// component, or the parent .crt sibling carries one of the
// curated tokens.
func IsAfipPath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, t := range AfipNameTokens() {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// DetectEndpointEnv inspects the path for production /
// homologación tokens. Heuristic; the audit pipeline can
// override with cert-Subject inspection downstream. Generic
// tokens (`prod`, `test`, `sandbox`) must appear as complete
// path components between slashes to avoid false positives
// from temp-dir names that embed "test".
func DetectEndpointEnv(path string) EndpointEnv {
	lower := strings.ToLower(filepath.ToSlash(path))
	prod := strings.Contains(lower, "produccion") ||
		strings.Contains(lower, "/production/") ||
		strings.Contains(lower, "/prod/") ||
		strings.HasSuffix(lower, ".prod.crt") ||
		strings.HasSuffix(lower, ".prod.key") ||
		strings.Contains(lower, "wsaa.afip.gov.ar")
	homo := strings.Contains(lower, "homologacion") ||
		strings.Contains(lower, "homologation") ||
		strings.Contains(lower, "wsaahomo") ||
		strings.Contains(lower, "/homo/") ||
		strings.Contains(lower, "/sandbox/") ||
		strings.Contains(lower, "/test/")
	switch {
	case prod && !homo:
		return EndpointProduction
	case homo && !prod:
		return EndpointHomologatio
	}
	return EndpointUnknown
}

// ClassifyByExtension maps a filesystem extension to an
// ArtifactKind. The walker still inspects content for TA-XML
// vs TRA-CMS vs cert disambiguation.
func ClassifyByExtension(path string) ArtifactKind {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".crt", ".cer", ".pem":
		return ArtifactCert
	case ".key":
		return ArtifactPrivateKey
	case ".p12", ".pfx":
		return ArtifactPKCS12
	case ".cms":
		return ArtifactTRACMS
	case ".xml":
		// Caller disambiguates ta-xml vs other via parser.
		return ArtifactUnknown
	case ".ini", ".cfg", ".json", ".yml", ".yaml":
		return ArtifactWSAAConfig
	}
	return ArtifactUnknown
}

// AnnotateSecurity sets the derived booleans. The caller must
// populate FileMode + ArtifactKind + scalar fields first.
func AnnotateSecurity(a *Artifact) {
	if a.FileMode != 0 {
		a.IsWorldReadable = a.FileMode&0o004 != 0
		a.IsGroupReadable = a.FileMode&0o040 != 0
	}
	switch a.ArtifactKind {
	case ArtifactPrivateKey:
		if a.IsPrivateKeyUnencrypted && (a.IsWorldReadable || a.IsGroupReadable) {
			a.IsCredentialExposureRisk = true
		}
	case ArtifactTAXML:
		if a.IsTaTokenPresent && !a.IsTaExpired && (a.IsWorldReadable || a.IsGroupReadable) {
			a.IsCredentialExposureRisk = true
		}
	case ArtifactCert, ArtifactPKCS12, ArtifactTRACMS, ArtifactWSAAConfig, ArtifactUnknown:
		// no rollup
	}
}

// SortArtifacts returns a deterministic ordering by file path,
// then artifact kind.
func SortArtifacts(as []Artifact) {
	sort.Slice(as, func(i, j int) bool {
		if as[i].FilePath != as[j].FilePath {
			return as[i].FilePath < as[j].FilePath
		}
		return as[i].ArtifactKind < as[j].ArtifactKind
	})
}
