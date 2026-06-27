// Package winargmercap audits Mercap broker back-office files
// cached on Argentine ALYC broker-dealer, FCI admin, and
// back-office-officer workstations across Windows, Linux, and
// macOS.
//
// Mercap (mercap.com.ar) is the dominant ALYC back-office
// software in Argentina (~60% market share among CNV-
// registered broker-dealers). It modules cover client
// gestión / KYC, liquidación T+1/T+2, tesorería cobros-pagos,
// contabilidad, and regulatory AIF / Régimen Informativo.
//
// **The broker back-office layer.** Distinct from:
//
//   - iter 107 winargcnvalyc   — ALYC business disclosure
//   - iter 117 winargcvsa      — CVSA central depository
//   - iter 142 winargccp       — CCP margin / settlement
//   - iter 138 winarguifros    — UIF / AML compliance
//   - iter 144 winargcnvrg1023 — cybersec compliance
//
// Headline finding shapes:
//
//   - `has_negative_cliente_balance=1` — saldo cliente < 0.
//   - `has_unreconciled_cvsa=1` — CVSA mismatch flagged.
//   - `has_overdue_settlement=1` — settlement > T+2.
//   - `has_commission_anomaly=1` — commission > 5% trade.
//   - `has_kyc_overdue=1` — KYC review > 12 months.
//   - `is_credential_exposure_risk=1` — readable file +
//     cliente CUIT + (balance OR KYC body OR commission).
//
// Read-only by intent. (Project guideline 4.2.)
package winargmercap

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
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// MaxSettlementDays — BYMA / MAE standard T+2 settlement.
const MaxSettlementDays = 2

// CommissionAnomalyPct — CNV RG 731 monitoring threshold.
// Commissions above this % of trade notional are anomalies.
const CommissionAnomalyPct = 5

// KYCOverdueDays — UIF Resol. 30/30-E annual review window.
const KYCOverdueDays = 365

// ArtifactKind pinned to host_arg_mercap.artifact_kind.
type ArtifactKind string

const (
	KindLiquidacionCV      ArtifactKind = "mercap-liquidacion-cv"
	KindConciliacionCVSA   ArtifactKind = "mercap-conciliacion-cvsa"
	KindSaldoCliente       ArtifactKind = "mercap-saldo-cliente"
	KindContabilidadCNV    ArtifactKind = "mercap-contabilidad-cnv"
	KindRegimenInformativo ArtifactKind = "mercap-regimen-informativo"
	KindCobrosPagos        ArtifactKind = "mercap-cobros-pagos"
	KindComisiones         ArtifactKind = "mercap-comisiones"
	KindKYCCliente         ArtifactKind = "mercap-kyc-cliente"
	KindCertificado        ArtifactKind = "mercap-certificado"
	KindConfig             ArtifactKind = "mercap-config"
	KindInstaller          ArtifactKind = "mercap-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// Module pinned to host_arg_mercap.module.
type Module string

const (
	ModuleGestionClientes Module = "gestion-clientes"
	ModuleContabilidad    Module = "contabilidad"
	ModuleLiquidacion     Module = "liquidacion"
	ModuleTesoreria       Module = "tesoreria"
	ModuleRegulatoryCNV   Module = "regulatory-cnv"
	ModuleRegulatoryUIF   Module = "regulatory-uif"
	ModuleRegulatoryAFIP  Module = "regulatory-afip"
	ModuleBackOffice      Module = "back-office"
	ModuleOther           Module = "other"
	ModuleUnknown         Module = "unknown"
)

// Row mirrors host_arg_mercap column shape.
type Row struct {
	FilePath                  string       `json:"file_path"`
	FileHash                  string       `json:"file_hash"`
	UserProfile               string       `json:"user_profile,omitempty"`
	ArtifactKind              ArtifactKind `json:"artifact_kind"`
	Module                    Module       `json:"module"`
	BrokerMatricula           string       `json:"broker_matricula,omitempty"`
	ClienteCuitPrefix         string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4        string       `json:"cliente_cuit_suffix4,omitempty"`
	CuentaComitenteSuffix4    string       `json:"cuenta_comitente_suffix4,omitempty"`
	KYCLastReviewDate         string       `json:"kyc_last_review_date,omitempty"`
	PeriodYYYYMM              string       `json:"period_yyyymm,omitempty"`
	SaldoClienteARSCents      int64        `json:"saldo_cliente_ars_cents,omitempty"`
	TotalSettlementARSCents   int64        `json:"total_settlement_ars_cents,omitempty"`
	MaxSettlementDays         int          `json:"max_settlement_days,omitempty"`
	CommissionPctMax          int          `json:"commission_pct_max,omitempty"`
	ReconciliationDiffCents   int64        `json:"reconciliation_diff_cents,omitempty"`
	FileOwnerUID              int          `json:"file_owner_uid,omitempty"`
	FileMode                  int          `json:"file_mode,omitempty"`
	FileSize                  int64        `json:"file_size,omitempty"`
	HasNegativeClienteBalance bool         `json:"has_negative_cliente_balance"`
	HasUnreconciledCVSA       bool         `json:"has_unreconciled_cvsa"`
	HasOverdueSettlement      bool         `json:"has_overdue_settlement"`
	HasCommissionAnomaly      bool         `json:"has_commission_anomaly"`
	HasKYCOverdue             bool         `json:"has_kyc_overdue"`
	HasUnreportedCNV          bool         `json:"has_unreported_cnv"`
	HasClienteCuit            bool         `json:"has_cliente_cuit"`
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

// DefaultInstallRoots is the curated Mercap install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Mercap`,
		`C:\Program Files\Mercap`,
		`C:\Program Files (x86)\Mercap`,
		`C:\Broker\Mercap`,
		`C:\BackOffice\Mercap`,
		`/opt/mercap`,
		`/srv/mercap`,
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

// UserMercapDirs is the curated per-user relative path set.
func UserMercapDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Mercap"},
		{"AppData", "Local", "Mercap"},
		{"Documents", "Mercap"},
		{"Documents", "Broker", "Mercap"},
		{"Documents", "BackOffice", "Mercap"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// Mercap artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".csv", ".tsv", ".json",
		".txt", ".log", ".pdf",
		".xlsx", ".xls",
		".ini", ".cfg", ".conf",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Mercap catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"mercap",
		"liquidacion_cv", "liquidacion-cv",
		"conciliacion_cvsa", "conciliacion-cvsa",
		"saldo_diario", "saldo-diario", "saldo_cliente",
		"contabilidad_cnv", "contabilidad-cnv",
		"regimen_informativo", "regimen-informativo",
		"cobros_pagos", "cobros-pagos",
		"comisiones_", "comisiones-",
		"kyc_cliente", "kyc-cliente",
		"certificado_op", "certificado-op",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// ArtifactKindFromName classifies a filename heuristically.
//
// Order matters: more-specific tokens precede generic ones.
func ArtifactKindFromName(name string) ArtifactKind {
	if strings.TrimSpace(name) == "" {
		return KindUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe":
		if strings.Contains(n, "mercap") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "liquidacion_cv") ||
		strings.Contains(n, "liquidacion-cv"):
		return KindLiquidacionCV
	case strings.Contains(n, "conciliacion_cvsa") ||
		strings.Contains(n, "conciliacion-cvsa"):
		return KindConciliacionCVSA
	case strings.Contains(n, "saldo_diario") ||
		strings.Contains(n, "saldo-diario") ||
		strings.Contains(n, "saldo_cliente"):
		return KindSaldoCliente
	case strings.Contains(n, "contabilidad_cnv") ||
		strings.Contains(n, "contabilidad-cnv"):
		return KindContabilidadCNV
	case strings.Contains(n, "regimen_informativo") ||
		strings.Contains(n, "regimen-informativo"):
		return KindRegimenInformativo
	case strings.Contains(n, "cobros_pagos") ||
		strings.Contains(n, "cobros-pagos"):
		return KindCobrosPagos
	case strings.Contains(n, "comisiones"):
		return KindComisiones
	case strings.Contains(n, "kyc_cliente") ||
		strings.Contains(n, "kyc-cliente"):
		return KindKYCCliente
	case strings.Contains(n, "certificado"):
		return KindCertificado
	case strings.Contains(n, "mercap") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf"):
		return KindConfig
	}
	return KindOther
}

// ModuleFromKind maps artifact kind to Mercap module.
func ModuleFromKind(k ArtifactKind) Module {
	switch k {
	case KindLiquidacionCV, KindConciliacionCVSA, KindComisiones,
		KindCertificado:
		return ModuleLiquidacion
	case KindSaldoCliente, KindCobrosPagos:
		return ModuleTesoreria
	case KindContabilidadCNV:
		return ModuleContabilidad
	case KindRegimenInformativo:
		return ModuleRegulatoryCNV
	case KindKYCCliente:
		return ModuleGestionClientes
	case KindConfig:
		return ModuleBackOffice
	case KindInstaller, KindOther, KindUnknown:
		return ModuleOther
	}
	return ModuleUnknown
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

// cuentaRE matches `comitente N°<digits>` / `cuenta=<digits>`.
var cuentaRE = regexp.MustCompile(`(?i)(?:comitente|cuenta)[\s:#=\.\-]{0,10}n?[°º]?[\s:#=]{0,5}(\d{4,12})`)

// CuentaSuffix4 extracts the last 4 digits of the cuenta-
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

// IsHighSensitivityKind reports whether the kind carries
// PII / financial-balance / commission-detail subject to
// the credential-exposure rollup.
func IsHighSensitivityKind(k ArtifactKind) bool {
	switch k {
	case KindSaldoCliente, KindCobrosPagos, KindKYCCliente,
		KindLiquidacionCV, KindConciliacionCVSA,
		KindComisiones, KindContabilidadCNV:
		return true
	case KindRegimenInformativo, KindCertificado, KindConfig,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsKYCOverdue reports whether the KYC review date is outside
// the UIF Resol. 30-E annual window.
func IsKYCOverdue(reviewDate string, now time.Time) bool {
	if reviewDate == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", reviewDate)
	if err != nil {
		return false
	}
	return now.Sub(t) > time.Duration(KYCOverdueDays)*24*time.Hour
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.SaldoClienteARSCents < 0 {
		r.HasNegativeClienteBalance = true
	}
	if r.ReconciliationDiffCents != 0 {
		r.HasUnreconciledCVSA = true
	}
	if r.MaxSettlementDays > MaxSettlementDays {
		r.HasOverdueSettlement = true
	}
	if r.CommissionPctMax >= CommissionAnomalyPct {
		r.HasCommissionAnomaly = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := IsHighSensitivityKind(r.ArtifactKind)
	if readable && r.HasClienteCuit && bodySignal {
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
