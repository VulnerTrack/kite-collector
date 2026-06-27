// Package winargbcrasiscen audits BCRA SISCEN (Régimen
// Informativo de Compraventa de Títulos Valores) artifact
// files cached on Argentine bank, ALYC broker-dealer, FCI
// sociedad-gerente, and FCI sociedad-depositaria workstations
// across Windows, Linux, and macOS.
//
// SISCEN is the **daily securities transaction reporting**
// regime mandated by BCRA Comunicación "A" 4856 and its
// subsequent updates. All entidades financieras (Banks and
// ALYCs registered with BCRA) and FCI managing companies must
// submit a fixed-width text file (typically named
// `A6356_YYYYMMDD.txt` or `COMPRAVENTA_YYYYMMDD.txt`) to the
// BCRA SISCEN portal containing per-transaction detail for
// the trading day.
//
// The SISCEN report carries:
//
//  1. AR sovereign bonds (AL30, GD30, AE38, LECAP, BONCER).
//  2. AR corporate ON (Obligaciones Negociables).
//  3. BYMA / Mercado Argentino equity.
//  4. FCI cuotapartes (subscription / redemption).
//  5. Repo (caución bursátil).
//  6. Forward and swap operations over securities.
//  7. Per-trade cliente CUIT, ticker, quantity, price, ISIN.
//
// **The BCRA SISCEN reporting layer.** Distinct from
// CNV-side filings (winargcnvaif) and AFIP-side tax reports
// (winargafiprg5193).
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — cfg cleartext.
//   - `has_bcra_portal_token=1` — portal token / cert.
//   - `has_siscen_report=1` — formatted SISCEN report.
//   - `has_sov_bonds=1` — AR sovereign bonds reported.
//   - `has_corp_on=1` — corporate ON reported.
//   - `has_byma_equity=1` — BYMA equity reported.
//   - `has_fci_cuotapartes=1` — FCI cuotapartes reported.
//   - `has_repo_caucion=1` — REPO / caución bursátil.
//   - `has_forward_ops=1` — forward securities ops.
//   - `has_swap_ops=1` — securities swap ops.
//   - `has_cliente_cuit_export=1` — full client CUIT roster.
//   - `has_rejection_log=1` — BCRA validation rejection.
//   - `has_high_value_trade=1` — single trade > USD 1 M.
//   - `has_foreign_resident=1` — non-AR cliente CUIT.
//   - `has_concentrated_counterparty=1` — single CP > 50 %.
//   - `is_credential_exposure_risk=1` — readable + (password
//     OR portal token OR client CUIT export OR rejection
//     log).
//
// Read-only by intent. (Project guideline 4.2.)
package winargbcrasiscen

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

// MaxFileBytes bounds per-file read (32 MiB — SISCEN reports
// for active banks can be large).
const MaxFileBytes = 32 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// HighValueTradeUSDCents — USD 1 000 000 in cents.
const HighValueTradeUSDCents int64 = 100_000_000

// ConcentratedCounterpartyThresholdPct — single counter-party
// volume share triggering concentration flag.
const ConcentratedCounterpartyThresholdPct = 50

// ArtifactKind pinned to host_arg_bcrasiscen.artifact_kind.
type ArtifactKind string

const (
	KindConfig       ArtifactKind = "siscen-config"
	KindCredentials  ArtifactKind = "siscen-credentials"  //#nosec G101 -- ArtifactKind enum naming the SISCEN credentials artifact category, not a credential value
	KindPortalToken  ArtifactKind = "siscen-portal-token" //#nosec G101 -- ArtifactKind enum naming the SISCEN portal-token artifact category, not a token value
	KindPortalCert   ArtifactKind = "siscen-portal-cert"
	KindReport       ArtifactKind = "siscen-report"
	KindTemplate     ArtifactKind = "siscen-template"
	KindRejectionLog ArtifactKind = "siscen-rejection-log"
	KindSourceDump   ArtifactKind = "siscen-source-dump"
	KindArchive      ArtifactKind = "siscen-archive"
	KindInstaller    ArtifactKind = "siscen-installer"
	KindOther        ArtifactKind = "other"
	KindUnknown      ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_bcrasiscen.account_class.
type AccountClass string

const (
	AccountEntidadFinanciera     AccountClass = "entidad-financiera"
	AccountALYC                  AccountClass = "alyc"
	AccountSociedadGerente       AccountClass = "sociedad-gerente"
	AccountSociedadDepositaria   AccountClass = "sociedad-depositaria"
	AccountAgenteCorredorCambios AccountClass = "agente-corredor-cambios"
	AccountAgenteFideicomiso     AccountClass = "agente-fideicomiso"
	AccountDemo                  AccountClass = "demo"
	AccountOther                 AccountClass = "other"
	AccountUnknown               AccountClass = "unknown"
)

// ProductClass pinned to host_arg_bcrasiscen.product_class.
type ProductClass string

const (
	ProductSovBondsTrades       ProductClass = "sov-bonds-trades"
	ProductCorpONTrades         ProductClass = "corp-on-trades"
	ProductEquityTrades         ProductClass = "equity-trades"
	ProductFCICuotapartesTrades ProductClass = "fci-cuotapartes-trades"
	ProductRepoCaucion          ProductClass = "repo-caucion"
	ProductForwardOps           ProductClass = "forward-ops"
	ProductSwapOps              ProductClass = "swap-ops"
	ProductMultiProduct         ProductClass = "multi-product"
	ProductOther                ProductClass = "other"
	ProductUnknown              ProductClass = "unknown"
)

// SISCENFormCode pinned to host_arg_bcrasiscen.siscen_form_code.
type SISCENFormCode string

const (
	FormA6356       SISCENFormCode = "A6356"
	FormA4856       SISCENFormCode = "A4856"
	FormA7724       SISCENFormCode = "A7724"
	FormCompraventa SISCENFormCode = "COMPRAVENTA"
	FormOther       SISCENFormCode = "other"
	FormUnknown     SISCENFormCode = ""
)

// Row mirrors host_arg_bcrasiscen column shape.
type Row struct {
	FilePath                    string         `json:"file_path"`
	FileHash                    string         `json:"file_hash"`
	UserProfile                 string         `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind   `json:"artifact_kind"`
	AccountClass                AccountClass   `json:"account_class"`
	ProductClass                ProductClass   `json:"product_class"`
	EntityCode                  string         `json:"entity_code,omitempty"`
	SISCENFormCode              SISCENFormCode `json:"siscen_form_code,omitempty"`
	ReportingDate               string         `json:"reporting_date,omitempty"`
	PeriodYYYYMM                string         `json:"period_yyyymm,omitempty"`
	ClienteCuitPrefix           string         `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4          string         `json:"cliente_cuit_suffix4,omitempty"`
	PortalTokenHash             string         `json:"portal_token_hash,omitempty"`
	UsernameHash                string         `json:"username_hash,omitempty"`
	TradeRecordCount            int64          `json:"trade_record_count,omitempty"`
	DistinctISINsCount          int64          `json:"distinct_isins_count,omitempty"`
	DistinctClientesCount       int64          `json:"distinct_clientes_count,omitempty"`
	DistinctCounterpartiesCount int64          `json:"distinct_counterparties_count,omitempty"`
	HighValueTradeCount         int64          `json:"high_value_trade_count,omitempty"`
	RejectionRecordCount        int64          `json:"rejection_record_count,omitempty"`
	SovBondRecordCount          int64          `json:"sov_bond_record_count,omitempty"`
	CorpONRecordCount           int64          `json:"corp_on_record_count,omitempty"`
	EquityRecordCount           int64          `json:"equity_record_count,omitempty"`
	FCIRecordCount              int64          `json:"fci_record_count,omitempty"`
	RepoRecordCount             int64          `json:"repo_record_count,omitempty"`
	ForwardRecordCount          int64          `json:"forward_record_count,omitempty"`
	SwapRecordCount             int64          `json:"swap_record_count,omitempty"`
	FileOwnerUID                int            `json:"file_owner_uid,omitempty"`
	FileMode                    int            `json:"file_mode,omitempty"`
	FileSize                    int64          `json:"file_size,omitempty"`
	HasPasswordInConfig         bool           `json:"has_password_in_config"`
	HasBCRAPortalToken          bool           `json:"has_bcra_portal_token"`
	HasSISCENReport             bool           `json:"has_siscen_report"`
	HasSovBonds                 bool           `json:"has_sov_bonds"`
	HasCorpON                   bool           `json:"has_corp_on"`
	HasBYMAEquity               bool           `json:"has_byma_equity"`
	HasFCICuotapartes           bool           `json:"has_fci_cuotapartes"`
	HasRepoCaucion              bool           `json:"has_repo_caucion"`
	HasForwardOps               bool           `json:"has_forward_ops"`
	HasSwapOps                  bool           `json:"has_swap_ops"`
	HasClienteCuitExport        bool           `json:"has_cliente_cuit_export"`
	HasRejectionLog             bool           `json:"has_rejection_log"`
	HasHighValueTrade           bool           `json:"has_high_value_trade"`
	HasForeignResident          bool           `json:"has_foreign_resident"`
	HasConcentratedCounterparty bool           `json:"has_concentrated_counterparty"`
	IsRecent                    bool           `json:"is_recent"`
	IsWorldReadable             bool           `json:"is_world_readable"`
	IsGroupReadable             bool           `json:"is_group_readable"`
	IsCredentialExposureRisk    bool           `json:"is_credential_exposure_risk"`
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

// HashSecret returns the SHA-256 hex of a normalized secret.
func HashSecret(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// DefaultInstallRoots is the curated SISCEN install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\BCRA`,
		`C:\BCRA\SISCEN`,
		`C:\BCRA\Portal`,
		`C:\BCRA\SISCEN\Reportes`,
		`C:\BCRA\SISCEN\Templates`,
		`C:\BCRA\SISCEN\Errors`,
		`C:\SISCEN`,
		`C:\Program Files\BCRA`,
		`C:\Program Files (x86)\BCRA`,
		`/opt/bcra`,
		`/opt/bcra-siscen`,
		`/opt/siscen`,
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

// UserSISCENDirs is the curated per-user relative path set.
func UserSISCENDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "BCRA"},
		{"AppData", "Roaming", "BCRA", "SISCEN"},
		{"AppData", "Local", "BCRA"},
		{"Documents", "BCRA"},
		{"Documents", "SISCEN"},
		{".config", "bcra-siscen"},
		{".config", "bcra"},
		{".bcra"},
		{"projects", "siscen"},
		{"Descargas"},
		{"Downloads"},
	}
}

// ARSovBondStems — AR sovereign-bond stems used in SISCEN
// reports (restructuring 2020/2021/2024 series, BONCER, LECAP,
// BONTE, BOPREAL).
func ARSovBondStems() []string {
	return []string{
		"AL29", "AL30", "AL35", "AL38", "AL41",
		"AE38", "GD29", "GD30", "GD35", "GD38",
		"GD41", "GD46",
		"AY24", "AO20", "AA21", "AA37", "AA46",
		"AL30D", "GD30D", "AL35D", "GD35D",
		"BONCER", "CER", "TX26", "TX28", "TX31",
		"BOPREAL", "BPY26", "BPA7", "BPB7", "BPC7",
		"PR13", "DICA", "DICY", "PARA", "PARY",
		"LECAP", "BONTE", "BONAR",
		"S31E5", "S29M4", "S30J4",
	}
}

// BYMAEquityTickers — BYMA equity stems most commonly traded.
func BYMAEquityTickers() []string {
	return []string{
		"GGAL", "YPFD", "PAMP", "EDN", "TXAR",
		"BMA", "BBAR", "TGSU2", "TGNO4",
		"ALUA", "TRAN", "VALO", "CRES", "MIRG",
		"CEPU", "COME", "BYMA", "AGRO", "CTIO",
		"BHIP", "BPAT", "SUPV", "FERR", "GARO",
	}
}

// IsARSovBondStem reports membership.
func IsARSovBondStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range ARSovBondStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsBYMAEquityTicker reports membership.
func IsBYMAEquityTicker(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range BYMAEquityTickers() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a
// SISCEN artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".txt", ".log", ".csv", ".tsv",
		".xml", ".json", ".ini", ".cfg", ".conf",
		".yaml", ".yml",
		".pfx", ".p12", ".pem", ".crt", ".cer",
		".tpl",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SISCEN catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"siscen", "bcra", "a6356", "a4856", "a7724",
		"compraventa", "compra_venta", "compra-venta",
		"titulos_valores", "titulos-valores", "tit_val",
		"reporte_diario", "reporte-diario",
		"rejection", "rechazo", "rechazos",
		"portal_token", "portal-token",
		"siscen_report", "siscen-report",
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
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "siscen") || strings.Contains(n, "bcra") {
			return KindInstaller
		}
		return KindOther
	case ".pfx", ".p12":
		return KindPortalCert
	case ".pem", ".crt", ".cer":
		if strings.Contains(n, "bcra") || strings.Contains(n, "siscen") ||
			strings.Contains(n, "portal") {
			return KindPortalCert
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "credentials") ||
		strings.Contains(n, "api_token") ||
		strings.Contains(n, "session_token"):
		return KindCredentials
	case strings.Contains(n, "portal_token") ||
		strings.Contains(n, "portal-token") ||
		strings.Contains(n, "bcra_token") ||
		strings.Contains(n, "bcra-token"):
		return KindPortalToken
	case strings.Contains(n, "rechazo") || strings.Contains(n, "rejection") ||
		(strings.Contains(n, "siscen") && strings.Contains(n, "error")):
		return KindRejectionLog
	case strings.Contains(n, "template") || strings.Contains(n, ".tpl") ||
		ext == ".tpl":
		return KindTemplate
	case strings.Contains(n, "archive") || strings.Contains(n, "historico") ||
		strings.Contains(n, "histórico"):
		return KindArchive
	case strings.Contains(n, "source_dump") || strings.Contains(n, "source-dump") ||
		strings.Contains(n, "dump_origen"):
		return KindSourceDump
	case strings.Contains(n, "a6356") || strings.Contains(n, "a4856") ||
		strings.Contains(n, "a7724") || strings.Contains(n, "compraventa") ||
		strings.Contains(n, "compra_venta") || strings.Contains(n, "compra-venta") ||
		strings.Contains(n, "titulos_valores") ||
		strings.Contains(n, "titulos-valores"):
		if ext == ".txt" || ext == ".csv" || ext == ".tsv" {
			return KindReport
		}
	case strings.Contains(n, "siscen") || strings.Contains(n, "bcra"):
		if ext == ".cfg" || ext == ".ini" || ext == ".json" ||
			ext == ".xml" || ext == ".yaml" || ext == ".yml" {
			return KindConfig
		}
		if ext == ".log" {
			return KindRejectionLog
		}
	}
	return KindOther
}

// SISCENFormFromName extracts the SISCEN form code from a
// filename heuristically.
func SISCENFormFromName(name string) SISCENFormCode {
	n := strings.ToUpper(filepath.Base(name))
	switch {
	case strings.Contains(n, "A6356"):
		return FormA6356
	case strings.Contains(n, "A4856"):
		return FormA4856
	case strings.Contains(n, "A7724"):
		return FormA7724
	case strings.Contains(n, "COMPRAVENTA") ||
		strings.Contains(n, "COMPRA_VENTA") ||
		strings.Contains(n, "COMPRA-VENTA"):
		return FormCompraventa
	}
	return FormUnknown
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

// PeriodFromFilename extracts YYYYMM from a filename.
func PeriodFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// ReportingDateFromFilename extracts YYYY-MM-DD from filename.
func ReportingDateFromFilename(name string) string {
	m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])`).
		FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return ""
	}
	return m[1] + "-" + m[2] + "-" + m[3]
}

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindConfig, KindCredentials, KindPortalToken, KindPortalCert,
		KindReport, KindTemplate, KindRejectionLog, KindSourceDump,
		KindArchive:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ArtifactKind == KindReport {
		r.HasSISCENReport = true
	}
	if r.ArtifactKind == KindPortalToken || r.ArtifactKind == KindPortalCert {
		r.HasBCRAPortalToken = true
	}
	if r.ArtifactKind == KindRejectionLog || r.RejectionRecordCount > 0 {
		r.HasRejectionLog = true
	}
	if r.SovBondRecordCount > 0 {
		r.HasSovBonds = true
	}
	if r.CorpONRecordCount > 0 {
		r.HasCorpON = true
	}
	if r.EquityRecordCount > 0 {
		r.HasBYMAEquity = true
	}
	if r.FCIRecordCount > 0 {
		r.HasFCICuotapartes = true
	}
	if r.RepoRecordCount > 0 {
		r.HasRepoCaucion = true
	}
	if r.ForwardRecordCount > 0 {
		r.HasForwardOps = true
	}
	if r.SwapRecordCount > 0 {
		r.HasSwapOps = true
	}
	if r.DistinctClientesCount > 0 {
		r.HasClienteCuitExport = true
	}
	if r.HighValueTradeCount > 0 {
		r.HasHighValueTrade = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInConfig || r.HasBCRAPortalToken ||
		r.HasClienteCuitExport || r.HasRejectionLog
	if readable && credSignal && IsCredentialKind(r.ArtifactKind) {
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
		return rs[i].ReportingDate < rs[j].ReportingDate
	})
}
