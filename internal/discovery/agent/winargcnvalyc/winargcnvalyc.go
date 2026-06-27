// Package winargcnvalyc audits Argentine CNV ALYC (Agente de
// Liquidación y Compensación) + ALYC-AN broker-dealer monthly
// regulatory disclosures cached on broker / custodian / risk /
// analyst workstations across Windows, Linux, and macOS.
//
// CNV requires every ALYC to file (via AIF) monthly:
//
//	RI Tenencias por Cliente      — custody balances per client
//	RI Operaciones por Especie    — transactions per security
//	Estados Patrimoniales         — broker capital adequacy
//	Custodia Mensual              — total AUM snapshot
//	R-IIR                         — Régimen Informativo
//	                                 Intermediarios y Registrantes
//
// **The broker-dealer regulatory-intermediary layer.**
// Complements iter 90 (CNV XBRL issuer position) + iter 97
// (CNV HR events) by capturing the intermediaries between
// investors and listed entities.
//
// Headline finding shapes:
//
//   - `has_foreign_currency_custody=1` — at least one custody
//     balance in USD/EUR. Capital-flight signal.
//   - `has_high_concentration=1` — single client > 50 % AUM.
//   - `client_count` — distinct cliente CUITs. Blast radius
//     when file is readable.
//   - `is_credential_exposure_risk=1` — readable file + client
//     CUIT list = Ley 25.326 + CNV RG 731 confidentiality
//     breach.
//
// All CUITs (broker + clients) reduced to entity-type prefix +
// last 4 digits.
//
// Read-only by intent. (Project guideline 4.2.)
package winargcnvalyc

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

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 16 << 20 // 16 MiB — broker disclosures can be large

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// HighConcentrationPct is the threshold above which
// has_high_concentration flips.
const HighConcentrationPct = 50

// MaxDenominacionChars bounds persisted denominación length.
const MaxDenominacionChars = 128

// FilingKind pinned to host_cnv_alyc_disclosures.filing_kind.
type FilingKind string

const (
	KindRITenencias          FilingKind = "ri-tenencias"
	KindRIOperaciones        FilingKind = "ri-operaciones"
	KindEstadosPatrimoniales FilingKind = "estados-patrimoniales"
	KindCustodiaMensual      FilingKind = "custodia-mensual"
	KindRegimenIIR           FilingKind = "regimen-iir"
	KindOther                FilingKind = "other"
	KindUnknown              FilingKind = "unknown"
)

// Row mirrors host_cnv_alyc_disclosures' column shape.
type Row struct {
	AlycDenominacion          string     `json:"alyc_denominacion,omitempty"`
	PeriodYYYYMM              string     `json:"period_yyyymm,omitempty"`
	AlycCuitSuffix4           string     `json:"alyc_cuit_suffix4,omitempty"`
	FilePath                  string     `json:"file_path"`
	FileHash                  string     `json:"file_hash"`
	UserProfile               string     `json:"user_profile,omitempty"`
	FilingKind                FilingKind `json:"filing_kind"`
	AlycMatricula             string     `json:"alyc_matricula,omitempty"`
	AlycCuitPrefix            string     `json:"alyc_cuit_prefix,omitempty"`
	ClientCount               int        `json:"client_count,omitempty"`
	FileOwnerUID              int        `json:"file_owner_uid,omitempty"`
	FileMode                  int        `json:"file_mode,omitempty"`
	FileSize                  int64      `json:"file_size,omitempty"`
	SpecieCount               int        `json:"specie_count,omitempty"`
	MaxClientPct              int        `json:"max_client_pct,omitempty"`
	TotalAumARSCents          int64      `json:"total_aum_ars_cents,omitempty"`
	IsGroupReadable           bool       `json:"is_group_readable"`
	HasHighConcentration      bool       `json:"has_high_concentration"`
	IsRecent                  bool       `json:"is_recent"`
	IsWorldReadable           bool       `json:"is_world_readable"`
	HasForeignCurrencyCustody bool       `json:"has_foreign_currency_custody"`
	IsCredentialExposureRisk  bool       `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated ALYC install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CNV\Agentes`,
		`C:\CNV\ALYC`,
		`C:\ALYC`,
		`C:\Brokers\CNV`,
		`/opt/cnv/agentes`,
		`/srv/cnv/alyc`,
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

// UserALYCDirs is the curated per-user relative path set.
func UserALYCDirs() [][]string {
	return [][]string{
		{"Documents", "CNV", "Agentes"},
		{"Documents", "CNV", "ALYC"},
		{"Documents", "ALYC"},
		{"Documents", "Compliance", "ALYC"},
		{"Documents", "Brokers"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the ALYC catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"alyc_", "alyc-",
		"ri_agentes", "ri-agentes", "regimen_informativo_agentes",
		"r-iir", "r_iir", "riir_",
		"tenencias_", "tenencias-",
		"custodia_", "custodia-",
		"estados_patrimoniales", "estados-patrimoniales",
		"agentes_mensual", "alyc_an",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// FilingKindFromName classifies a filename heuristically.
func FilingKindFromName(name string) FilingKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "tenencias"):
		return KindRITenencias
	case strings.Contains(n, "operaciones") &&
		(strings.Contains(n, "especie") || strings.Contains(n, "alyc")):
		return KindRIOperaciones
	case strings.Contains(n, "estados_patrimoniales") ||
		strings.Contains(n, "estados-patrimoniales"):
		return KindEstadosPatrimoniales
	case strings.Contains(n, "custodia"):
		return KindCustodiaMensual
	case strings.Contains(n, "r-iir") || strings.Contains(n, "r_iir") ||
		strings.Contains(n, "riir_"):
		return KindRegimenIIR
	case strings.Contains(n, "alyc") || strings.Contains(n, "ri_agentes") ||
		strings.Contains(n, "ri-agentes"):
		return KindOther
	}
	return KindUnknown
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

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitFingerprint extracts (prefix, suffix4) from text.
func CuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// matriculaRE matches CNV broker matrícula patterns. Allows
// up to ~30 chars of word / whitespace / separator between the
// keyword and the digits to catch forms like "matricula CNV 338".
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|mat[\.\-]?cnv|alyc[_-]matricula)[\s:#=\w\.\-]{0,30}?(\d{2,5})`)

// MatriculaFromText extracts the CNV broker matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// periodRE matches YYYYMM embedded in filenames.
var periodRE = regexp.MustCompile(`(20\d{2})[-_]?(0[1-9]|1[0-2])`)

// PeriodFromName extracts a YYYYMM period from filename.
func PeriodFromName(name string) string {
	m := periodRE.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// TruncateString shortens a string preserving UTF-8.
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

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.MaxClientPct > HighConcentrationPct {
		r.HasHighConcentration = true
	}
	// PII exposure: client list present + readable.
	if r.ClientCount > 0 && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].AlycCuitPrefix != rs[j].AlycCuitPrefix {
			return rs[i].AlycCuitPrefix < rs[j].AlycCuitPrefix
		}
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
