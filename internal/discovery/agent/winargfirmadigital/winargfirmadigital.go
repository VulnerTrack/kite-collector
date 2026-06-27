// Package winargfirmadigital audits Argentine ONTI-accredited
// firma-digital certificate stores on contador / escribano /
// abogado / sociedad workstations across Windows, Linux, and
// macOS.
//
// Ley 25.506 makes firma digital legally equivalent to a
// manuscript signature when issued by an ONTI-accredited CA
// (AC-Modernización, AC-Raíz República Argentina, AC-ONTI,
// AC-ARCA / AC-AFIP).
//
// **Distinct from iter 88 winafipwsaa** (which is AFIP-WSAA-
// specific B2B-soap authentication). This collector targets
// general-purpose document-signing certs across multiple
// accredited issuers.
//
// Headline finding shapes:
//
//   - `is_expired=1` — hygiene gap; cert still on disk after
//     rotation needed.
//   - `is_expiring_soon=1` — valid_to ≤ 30 days from now.
//   - `is_legally_binding=1` — ONTI-accredited issuer + not
//     expired = manuscript-equivalent signature capability.
//   - `is_soft_cert_with_key=1` — PFX/P12 bundle on disk
//     (private key not in hardware token).
//   - `is_credential_exposure_risk=1` — soft-cert-with-key +
//     readable beyond owner. T1552.004 key-theft surface.
//
// CUIL/CUIT (when extractable from Subject DN serialNumber)
// reduced to entity-type prefix + last 4 digits.
//
// Read-only by intent. (Project guideline 4.2.)
package winargfirmadigital

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
const MaxRows = 8192

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 1 << 20 // 1 MiB

// ExpiringSoonWindow defines the cutoff for is_expiring_soon.
const ExpiringSoonWindow = 30 * 24 * time.Hour

// MaxSubjectCNChars bounds persisted Subject CN length.
const MaxSubjectCNChars = 128

// CertKind pinned to host_arg_firma_digital.cert_kind.
type CertKind string

const (
	KindSoftPFX CertKind = "soft-cert-pfx"
	KindSoftP12 CertKind = "soft-cert-p12"
	KindX509PEM CertKind = "x509-pem"
	KindX509DER CertKind = "x509-der"
	KindCACert  CertKind = "ca-cert"
	KindKeyOnly CertKind = "key-only"
	KindOther   CertKind = "other"
	KindUnknown CertKind = "unknown"
)

// IssuerCA pinned to host_arg_firma_digital.issuer_ca.
type IssuerCA string

const (
	IssuerONTI            IssuerCA = "onti"
	IssuerACModernizacion IssuerCA = "ac-modernizacion"
	IssuerACRaizRepArg    IssuerCA = "ac-raiz-republica-argentina"
	IssuerACARCA          IssuerCA = "ac-arca"
	IssuerACAFIP          IssuerCA = "ac-afip"
	IssuerACCamerfirma    IssuerCA = "ac-camerfirma"
	IssuerACEncode        IssuerCA = "ac-encode"
	IssuerOther           IssuerCA = "other"
	IssuerUnknown         IssuerCA = "unknown"
)

// Row mirrors host_arg_firma_digital' column shape.
type Row struct {
	SubjectCuitSuffix4       string   `json:"subject_cuit_suffix4,omitempty"`
	ValidFrom                string   `json:"valid_from,omitempty"`
	SubjectCuitPrefix        string   `json:"subject_cuit_prefix,omitempty"`
	FilePath                 string   `json:"file_path"`
	FileHash                 string   `json:"file_hash"`
	UserProfile              string   `json:"user_profile,omitempty"`
	CertKind                 CertKind `json:"cert_kind"`
	IssuerCA                 IssuerCA `json:"issuer_ca"`
	SubjectCN                string   `json:"subject_cn,omitempty"`
	ValidTo                  string   `json:"valid_to,omitempty"`
	FileOwnerUID             int      `json:"file_owner_uid,omitempty"`
	FileMode                 int      `json:"file_mode,omitempty"`
	FileSize                 int64    `json:"file_size,omitempty"`
	DaysToExpiry             int      `json:"days_to_expiry,omitempty"`
	IsExpired                bool     `json:"is_expired"`
	IsExpiringSoon           bool     `json:"is_expiring_soon"`
	IsONTIAccredited         bool     `json:"is_onti_accredited"`
	IsLegallyBinding         bool     `json:"is_legally_binding"`
	IsSoftCertWithKey        bool     `json:"is_soft_cert_with_key"`
	IsWorldReadable          bool     `json:"is_world_readable"`
	IsGroupReadable          bool     `json:"is_group_readable"`
	IsCredentialExposureRisk bool     `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated firma-digital root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\FirmaDigital`,
		`C:\ONTI`,
		`C:\AC-Modernizacion`,
		`C:\Certificados`,
		`/opt/firma-digital`,
		`/srv/firma-digital`,
	}
}

// DefaultUsersBases is the curated per-OS user-profile bases.
func DefaultUsersBases() []string {
	return []string{
		`C:\Users`,
		"/home",
		"/Users",
	}
}

// UserFirmaDirs is the curated per-user relative path set.
func UserFirmaDirs() [][]string {
	return [][]string{
		{"Documents", "FirmaDigital"},
		{"Documents", "Certificados"},
		{"Documents", "ONTI"},
		{"Documents", "AC-Modernizacion"},
		{"Documents", "Compliance", "Certificados"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsAfipWsaaPath reports whether the path belongs to the
// AFIP-WSAA collector's coverage area (iter 88). We skip
// these to avoid double-coverage.
func IsAfipWsaaPath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, tok := range []string{
		"afip", "arca", "wsaa", "wsfe", "wsfev1",
		"wsmtxca", "pyafipws", "afipsdk",
	} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the firma-digital catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"firma_digital", "firma-digital", "firmadigital",
		"onti_", "onti-", "ac_modernizacion", "ac-modernizacion",
		"ac_raiz", "ac-raiz", "cert_firma", "certificado",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a cert
// / key bundle.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pfx", ".p12", ".cer", ".crt", ".pem", ".der", ".key":
		return true
	}
	return false
}

// CertKindFromExt classifies the file by extension.
func CertKindFromExt(name string) CertKind {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pfx":
		return KindSoftPFX
	case ".p12":
		return KindSoftP12
	case ".pem":
		return KindX509PEM
	case ".cer", ".der":
		return KindX509DER
	case ".crt":
		return KindX509PEM
	case ".key":
		return KindKeyOnly
	}
	return KindUnknown
}

// IssuerCAFromText classifies an Issuer DN string. Accepts
// both accented and unaccented forms (`Raíz` / `Raiz`,
// `Modernización` / `Modernizacion`) because Go's x509 library
// preserves the accents from the cert DN.
func IssuerCAFromText(issuer string) IssuerCA {
	t := strings.ToLower(issuer)
	switch {
	case t == "":
		return IssuerUnknown
	case strings.Contains(t, "ac-raiz") || strings.Contains(t, "ac raiz") ||
		strings.Contains(t, "ac-raíz") || strings.Contains(t, "ac raíz") ||
		strings.Contains(t, "raíz república argentina") ||
		strings.Contains(t, "raiz república argentina") ||
		strings.Contains(t, "raiz republica argentina"):
		return IssuerACRaizRepArg
	case strings.Contains(t, "modernizaci"):
		// Catches Modernización / Modernizacion / AC-Modernización
		// / Ministerio de Modernización in any spelling form.
		return IssuerACModernizacion
	case strings.Contains(t, "ac-arca") || strings.Contains(t, "ac arca") ||
		strings.Contains(t, "arca ca"):
		return IssuerACARCA
	case strings.Contains(t, "ac-afip") || strings.Contains(t, "ac afip") ||
		strings.Contains(t, "afip ca"):
		return IssuerACAFIP
	case strings.Contains(t, "ac-onti") || strings.Contains(t, "ac onti") ||
		strings.Contains(t, "onti"):
		return IssuerONTI
	case strings.Contains(t, "camerfirma"):
		return IssuerACCamerfirma
	case strings.Contains(t, "encode"):
		return IssuerACEncode
	}
	return IssuerOther
}

// IsONTIAccreditedIssuer reports whether the IssuerCA is one
// of the curated ONTI-accredited authorities.
func IsONTIAccreditedIssuer(ca IssuerCA) bool {
	switch ca {
	case IssuerONTI, IssuerACModernizacion, IssuerACRaizRepArg,
		IssuerACARCA, IssuerACAFIP:
		return true
	case IssuerACCamerfirma, IssuerACEncode, IssuerOther, IssuerUnknown:
		return false
	}
	return false
}

// CuitEntityPrefixes mirrors AFIP collector list.
func CuitEntityPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitEntityPrefix reports prefix membership.
func IsValidCuitEntityPrefix(p string) bool {
	for _, v := range CuitEntityPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches `CUIT XX-XXXXXXXX-X` or bare 11-digit run.
var cuitRE = regexp.MustCompile(`(?i)(?:CUIT|CUIL)\s*[: ]?\s*(\d{2})-?(\d{8})-?(\d)|(?:^|\D)(\d{11})(?:\D|$)`)

// CuitFingerprintFromText extracts (prefix, suffix4) from a
// subject-DN string. Empty / non-match returns "", "".
func CuitFingerprintFromText(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	if m[1] != "" {
		prefix = m[1]
		mid := m[2]
		check := m[3]
		suffix4 = mid[len(mid)-3:] + check
	} else if m[4] != "" {
		bare := m[4]
		prefix = bare[:2]
		suffix4 = bare[7:]
	}
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// TruncateString shortens preserving UTF-8.
func TruncateString(s string, max int) string {
	t := strings.TrimSpace(s)
	if len(t) <= max {
		return t
	}
	r := []rune(t)
	if len(r) <= max {
		return t
	}
	return string(r[:max])
}

// ClockFn is the injectable clock.
type ClockFn func() time.Time

// AnnotateSecurityWithClock sets derived booleans, using the
// provided clock for expiry computations.
func AnnotateSecurityWithClock(r *Row, now ClockFn) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	r.IsONTIAccredited = IsONTIAccreditedIssuer(r.IssuerCA)
	// Soft-cert-with-key heuristic: PFX/P12 bundles always
	// carry private keys.
	if r.CertKind == KindSoftPFX || r.CertKind == KindSoftP12 ||
		r.CertKind == KindKeyOnly {
		r.IsSoftCertWithKey = true
	}
	// Expiry computation.
	if r.ValidTo != "" && now != nil {
		if expiry, ok := parseTime(r.ValidTo); ok {
			current := now()
			delta := expiry.Sub(current)
			r.DaysToExpiry = int(delta / (24 * time.Hour))
			if delta < 0 {
				r.IsExpired = true
			} else if delta <= ExpiringSoonWindow {
				r.IsExpiringSoon = true
			}
		}
	}
	r.IsLegallyBinding = r.IsONTIAccredited && !r.IsExpired
	// T1552.004 exposure: soft-cert-with-key + readable beyond
	// owner.
	if r.IsSoftCertWithKey && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// AnnotateSecurity is the time.Now-clock convenience.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02/01/2006",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].IssuerCA != rs[j].IssuerCA {
			return rs[i].IssuerCA < rs[j].IssuerCA
		}
		return rs[i].SubjectCN < rs[j].SubjectCN
	})
}
