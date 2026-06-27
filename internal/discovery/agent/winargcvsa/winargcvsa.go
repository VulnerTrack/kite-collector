// Package winargcvsa audits Caja de Valores S.A. (CVSA)
// custody-account files cached on ALYC broker, custodian,
// and back-office workstations across Windows, Linux, and
// macOS.
//
// CVSA is Argentina's central securities depository (CSD).
// Every BYMA / MAE / MAV-listed security is held in a
// cuenta comitente. Cached cuenta_comitente_*.xml files
// carry cliente CUIT + ticker-level holdings — AML/FATCA-
// grade exposure surface.
//
// **Distinct from**:
//   - iter 107 winargcnvalyc      — ALYC broker disclosure
//   - iter 109 winargmatbarofex   — derivatives positions
//   - iter 110 winargfci          — FCI mutual-fund layer
//   - iter 111 winargpymebursatil — PyME instrument-level
//   - iter 113 winargfix          — wire-protocol logs
//
// Headline finding shapes:
//
//   - `has_foreign_owner=1` — cliente CUIT carries
//     foreign-residence marker.
//   - `has_high_concentration=1` — single ticker > 50 %
//     of account market value.
//   - `has_large_holdings=1` — total > 100 M ARS.
//   - `has_cotitulares=1` — > 1 account holder.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + holdings detail.
//
// Read-only by intent. (Project guideline 4.2.)
package winargcvsa

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

// MaxFileBytes bounds per-file read (24 MiB — custody dumps
// can hold thousands of positions).
const MaxFileBytes = 24 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// LargeHoldingsCents — 100 M ARS = 10 G cents.
const LargeHoldingsCents int64 = 10_000_000_000

// HighConcentrationPct — single-instrument concentration
// threshold (in %) for has_high_concentration.
const HighConcentrationPct = 50

// ArtifactKind pinned to host_arg_cvsa_custody.artifact_kind.
type ArtifactKind string

const (
	KindCuentaComitente   ArtifactKind = "cuenta-comitente"
	KindTenenciasBroker   ArtifactKind = "tenencias-broker"
	KindSaldosClientes    ArtifactKind = "saldos-clientes"
	KindLiquidacionTitulo ArtifactKind = "liquidacion-titulos"
	KindTransferenciaDVP  ArtifactKind = "transferencia-dvp"
	KindDRRRestringidas   ArtifactKind = "drr-restringidas"
	KindTitulares         ArtifactKind = "titulares"
	KindCDAArchive        ArtifactKind = "cda-archive"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// Row mirrors host_arg_cvsa_custody' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	BrokerMatricula          string       `json:"broker_matricula,omitempty"`
	BrokerCuitPrefix         string       `json:"broker_cuit_prefix,omitempty"`
	BrokerCuitSuffix4        string       `json:"broker_cuit_suffix4,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	CuentaComitenteSuffix4   string       `json:"cuenta_comitente_suffix4,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	InstrumentCount          int64        `json:"instrument_count,omitempty"`
	CotitularesCount         int64        `json:"cotitulares_count,omitempty"`
	MaxPositionARSCents      int64        `json:"max_position_ars_cents,omitempty"`
	TotalPositionARSCents    int64        `json:"total_position_ars_cents,omitempty"`
	MaxPositionPct           int          `json:"max_position_pct,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasForeignOwner          bool         `json:"has_foreign_owner"`
	HasHighConcentration     bool         `json:"has_high_concentration"`
	HasLargeHoldings         bool         `json:"has_large_holdings"`
	HasCotitulares           bool         `json:"has_cotitulares"`
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

// DefaultInstallRoots is the curated CVSA install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CajadeValores`,
		`C:\CVSA\custodia`,
		`C:\Custodia\CajaValores`,
		`C:\Broker\CVSA`,
		`C:\BackOffice\CVSA`,
		`/opt/cvsa`,
		`/opt/cajadevalores`,
		`/srv/cvsa/custodia`,
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

// UserCVSADirs is the curated per-user relative path set.
func UserCVSADirs() [][]string {
	return [][]string{
		{"Documents", "CajadeValores"},
		{"Documents", "CVSA"},
		{"Documents", "Custodia"},
		{"Documents", "Broker", "CVSA"},
		{"Documents", "BackOffice", "Custodia"},
		{"AppData", "Local", "CVSA"},
		{"AppData", "Roaming", "CVSA"},
	}
}

// IsCandidateExt reports whether the extension carries a
// CVSA artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".csv", ".cda", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the CVSA catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".cda" {
		return true
	}
	for _, tok := range []string{
		"cuenta_comitente", "cuenta-comitente", "comitente_",
		"tenencias_", "tenencias-",
		"saldos_clientes", "saldos-clientes",
		"liquidacion_titulos", "liquidacion-titulos",
		"transferencia_dvp", "transferencia-dvp",
		"drr_", "drr-", "_drr.",
		"titulares_", "titulares-",
		"caja_valores", "caja-valores",
		"cajavalores", "cvsa_", "cvsa-",
		"custodia_", "custodia-",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".cda" {
		return KindCDAArchive
	}
	switch {
	case strings.Contains(n, "cuenta_comitente") ||
		strings.Contains(n, "cuenta-comitente") ||
		strings.Contains(n, "comitente_"):
		return KindCuentaComitente
	case strings.Contains(n, "tenencias"):
		return KindTenenciasBroker
	case strings.Contains(n, "saldos_clientes") ||
		strings.Contains(n, "saldos-clientes"):
		return KindSaldosClientes
	case strings.Contains(n, "liquidacion_titulos") ||
		strings.Contains(n, "liquidacion-titulos"):
		return KindLiquidacionTitulo
	case strings.Contains(n, "transferencia_dvp") ||
		strings.Contains(n, "transferencia-dvp"):
		return KindTransferenciaDVP
	case strings.Contains(n, "drr"):
		return KindDRRRestringidas
	case strings.Contains(n, "titulares"):
		return KindTitulares
	}
	return KindOther
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

// IsBrokerCuitPrefix reports prefix is juridical-broker type
// (30/33/34).
func IsBrokerCuitPrefix(p string) bool {
	switch p {
	case "30", "33", "34":
		return true
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

// matriculaRE matches CNV broker matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:matr[íi]cula|alyc[_-]matricula|broker[_-]matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts CNV broker matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// cuentaRE matches an explicit "comitente N°<digits>" pattern.
var cuentaRE = regexp.MustCompile(`(?i)(?:comitente|cuenta)[\s:#=\.\-]{0,10}n?[°º]?[\s:#=]{0,5}(\d{4,12})`)

// CuentaSuffix4 extracts the last 4 digits of the cuenta
// comitente number for fingerprinting.
func CuentaSuffix4(text string) string {
	m := cuentaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	n := m[1]
	if len(n) <= 4 {
		return n
	}
	return n[len(n)-4:]
}

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// AnnotateSecurity sets derived booleans. Caller populates
// FileMode + scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.TotalPositionARSCents > LargeHoldingsCents {
		r.HasLargeHoldings = true
	}
	if r.MaxPositionPct >= HighConcentrationPct {
		r.HasHighConcentration = true
	}
	if r.CotitularesCount > 1 {
		r.HasCotitulares = true
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasHoldingsDetail := r.InstrumentCount > 0 || r.TotalPositionARSCents > 0
	if hasReadable && r.ClienteCuitPrefix != "" && hasHoldingsDetail {
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
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
