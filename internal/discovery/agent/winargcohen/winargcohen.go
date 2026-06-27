// Package winargcohen audits Cohen Aliados Financieros (Cohen
// S.A.) artifact files cached on Argentine retail-and-institutional
// ALYC client workstations across Windows, Linux (via Wine), and
// macOS.
//
// Cohen Aliados Financieros is a top-5 AR ALYC (Agente de
// Liquidación y Compensación under CNV RG 731) and FCI agent
// through Cohen Asset Management (Cohen AM). Cohen uniquely
// combines:
//
//   - Cohen NetTrader desktop terminal (.cohen / .cnt profile).
//   - Cohen Mobile OAuth2 (refresh tokens cached locally).
//   - Cohen AM FCI suscripcion / rescate / cuotaparte receipts.
//   - Cohen Equity Research PDFs (analyst reports).
//   - SAGGM Galileo / Mariva back-office channel.
//
// Headline finding shapes:
//
//   - `has_password_in_profile=1` — profile cleartext.
//   - `has_oauth_refresh_token=1` — mobile OAuth cached.
//   - `has_fci_subscription=1` — Cohen AM suscripcion.
//   - `has_cuotaparte_record=1` — Cohen AM cuotaparte.
//   - `has_liquidacion_pdf=1` — daily liquidación.
//   - `has_saggm_backoffice=1` — SAGGM Galileo/Mariva.
//   - `has_fix_session=1` — FIX session cfg.
//   - `has_institutional_class=1` — cuotaparte > 1000.
//   - `is_credential_exposure_risk=1` — readable + (password OR
//     oauth OR FCI receipt OR liquidacion OR cliente CUIT).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcohen

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

// MaxFileBytes bounds per-file read (16 MiB).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// InstitutionalCuotaparteThreshold — CNV RG 622 art.50 +
// FATCA / CRS class-share threshold. > 1000 cuotapartes in a
// single receipt = institutional class share.
const InstitutionalCuotaparteThreshold = 1000

// ArtifactKind pinned to host_arg_cohen.artifact_kind.
type ArtifactKind string

const (
	KindProfile           ArtifactKind = "cohen-profile"
	KindSessionToken      ArtifactKind = "cohen-session-token"
	KindMobileOAuth       ArtifactKind = "cohen-mobile-oauth"
	KindFCISubscription   ArtifactKind = "cohen-fci-subscription"
	KindFCIRedemption     ArtifactKind = "cohen-fci-redemption"
	KindCuotaparteRecord  ArtifactKind = "cohen-cuotaparte-record"
	KindLiquidacionPDF    ArtifactKind = "cohen-liquidacion-pdf"
	KindResearchPDF       ArtifactKind = "cohen-research-pdf"
	KindSAGGMConfig       ArtifactKind = "cohen-saggm-config"
	KindFIXSession        ArtifactKind = "cohen-fix-session"
	KindTradeConfirmation ArtifactKind = "cohen-trade-confirmation"
	KindStatement         ArtifactKind = "cohen-statement"
	KindInstaller         ArtifactKind = "cohen-installer"
	KindOther             ArtifactKind = "other"
	KindUnknown           ArtifactKind = "unknown"
)

// AccountClass pinned to host_arg_cohen.account_class.
type AccountClass string

const (
	AccountRetailCliente            AccountClass = "retail-cliente"
	AccountInstitutionalCliente     AccountClass = "institutional-cliente"
	AccountFCICuotapartista         AccountClass = "fci-cuotapartista"
	AccountEquityResearchSubscriber AccountClass = "equity-research-subscriber"
	AccountFIXCounterparty          AccountClass = "fix-counterparty"
	AccountComplianceOfficer        AccountClass = "compliance-officer"
	AccountAPI                      AccountClass = "api"
	AccountDemo                     AccountClass = "demo"
	AccountOther                    AccountClass = "other"
	AccountUnknown                  AccountClass = "unknown"
)

// ProductClass pinned to host_arg_cohen.product_class.
type ProductClass string

const (
	ProductAREquity   ProductClass = "ar-equity"
	ProductARBond     ProductClass = "ar-bond"
	ProductARFCI      ProductClass = "ar-fci"
	ProductCEDEAR     ProductClass = "cedear"
	ProductUSEquity   ProductClass = "us-equity"
	ProductUSBond     ProductClass = "us-bond"
	ProductMEPDollar  ProductClass = "mep-dollar"
	ProductCCLDollar  ProductClass = "ccl-dollar"
	ProductMultiAsset ProductClass = "multi-asset"
	ProductOther      ProductClass = "other"
	ProductUnknown    ProductClass = "unknown"
)

// BackofficeChannel pinned to host_arg_cohen.backoffice_channel.
type BackofficeChannel string

const (
	BackofficeSAGGMGalileo BackofficeChannel = "saggm-galileo"
	BackofficeSAGGMMariva  BackofficeChannel = "saggm-mariva"
	BackofficeCohenDirect  BackofficeChannel = "cohen-direct"
	BackofficeSintesis     BackofficeChannel = "sintesis"
	BackofficeCustom       BackofficeChannel = "custom"
	BackofficeNone         BackofficeChannel = "none"
	BackofficeUnknown      BackofficeChannel = "unknown"
)

// Row mirrors host_arg_cohen column shape.
type Row struct {
	FilePath                 string            `json:"file_path"`
	FileHash                 string            `json:"file_hash"`
	UserProfile              string            `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind      `json:"artifact_kind"`
	AccountClass             AccountClass      `json:"account_class"`
	ProductClass             ProductClass      `json:"product_class"`
	BackofficeChannel        BackofficeChannel `json:"backoffice_channel,omitempty"`
	ClienteCuitPrefix        string            `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string            `json:"cliente_cuit_suffix4,omitempty"`
	CuentaComitente          string            `json:"cuenta_comitente,omitempty"`
	OAuthTokenHash           string            `json:"oauth_token_hash,omitempty"`
	UsernameHash             string            `json:"username_hash,omitempty"`
	FIXSenderCompID          string            `json:"fix_sender_comp_id,omitempty"`
	PeriodYYYYMM             string            `json:"period_yyyymm,omitempty"`
	DistinctSymbolsCount     int64             `json:"distinct_symbols_count,omitempty"`
	AREquitySymbolsCount     int64             `json:"ar_equity_symbols_count,omitempty"`
	CEDEARSymbolsCount       int64             `json:"cedear_symbols_count,omitempty"`
	CuotaparteCount          int64             `json:"cuotaparte_count,omitempty"`
	ResearchPDFCount         int64             `json:"research_pdf_count,omitempty"`
	LiquidacionCount         int64             `json:"liquidacion_count,omitempty"`
	FileOwnerUID             int               `json:"file_owner_uid,omitempty"`
	FileMode                 int               `json:"file_mode,omitempty"`
	FileSize                 int64             `json:"file_size,omitempty"`
	HasPasswordInProfile     bool              `json:"has_password_in_profile"`
	HasOAuthRefreshToken     bool              `json:"has_oauth_refresh_token"`
	HasFCISubscription       bool              `json:"has_fci_subscription"`
	HasFCIRedemption         bool              `json:"has_fci_redemption"`
	HasCuotaparteRecord      bool              `json:"has_cuotaparte_record"`
	HasLiquidacionPDF        bool              `json:"has_liquidacion_pdf"`
	HasResearchPDF           bool              `json:"has_research_pdf"`
	HasSAGGMBackoffice       bool              `json:"has_saggm_backoffice"`
	HasFIXSession            bool              `json:"has_fix_session"`
	HasCuentaComitente       bool              `json:"has_cuenta_comitente"`
	HasInstitutionalClass    bool              `json:"has_institutional_class"`
	HasClienteCuit           bool              `json:"has_cliente_cuit"`
	IsRecent                 bool              `json:"is_recent"`
	IsWorldReadable          bool              `json:"is_world_readable"`
	IsGroupReadable          bool              `json:"is_group_readable"`
	IsCredentialExposureRisk bool              `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated Cohen install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Program Files\Cohen NetTrader`,
		`C:\Program Files (x86)\Cohen NetTrader`,
		`C:\Cohen`,
		"/opt/cohen",
		"/opt/cohen-nettrader",
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

// UserCohenDirs is the curated per-user relative path set.
func UserCohenDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "Cohen NetTrader"},
		{"AppData", "Roaming", "Cohen Mobile"},
		{"AppData", "Roaming", "Cohen AM"},
		{"AppData", "Roaming", "Cohen"},
		{"AppData", "Local", "Cohen NetTrader"},
		{"AppData", "Local", "Cohen Mobile"},
		{"AppData", "Local", "Cohen AM"},
		{"AppData", "Local", "Cohen"},
		{".cohen"},
		{".config", "cohen"},
		{"Documents", "Cohen"},
		{"Library", "Application Support", "Cohen NetTrader"},
		{"Library", "Application Support", "Cohen"},
		{"Descargas"},
		{"Downloads"},
	}
}

// AREquityCommonStems is the curated AR equity ticker set on
// BYMA / Merval (Cohen's home market).
func AREquityCommonStems() []string {
	return []string{
		// Top Merval (panel líder)
		"GGAL", "BMA", "BBAR", "SUPV", "VALO",
		"YPFD", "PAMP", "TGSU2", "TGNO4", "TRAN",
		"ALUA", "TXAR", "EDN", "CEPU", "CRES",
		"COME", "MIRG", "BYMA", "LOMA", "CVH",
		// MAV / regional
		"AGRO", "SAMI", "CAPX",
		// Bonds — soberanos
		"AL30", "AL35", "AL41", "AE38",
		"GD30", "GD35", "GD38", "GD41", "GD46",
		// MEP / CCL proxies
		"AY24", "DICA",
	}
}

// CEDEARCommonStems is the curated CEDEAR (AR-listed receipts
// on US/global equity) ticker set.
func CEDEARCommonStems() []string {
	return []string{
		"AAPL", "MSFT", "AMZN", "GOOGL", "META",
		"TSLA", "NVDA", "AMD", "INTC", "QCOM",
		"NFLX", "DIS", "BA", "JPM", "BAC",
		"WMT", "KO", "PEP", "MCD", "NKE",
		"MELI", "GLOB", "DESP", "BIOX",
	}
}

// IsAREquityStem reports membership in the AR equity set.
func IsAREquityStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range AREquityCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCEDEARStem reports membership in the CEDEAR set.
func IsCEDEARStem(s string) bool {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return false
	}
	for _, v := range CEDEARCommonStems() {
		if v == t {
			return true
		}
	}
	return false
}

// IsCandidateExt reports whether the extension carries a Cohen
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".cohen", ".cnt",
		".cfg", ".ini", ".json", ".xml",
		".csv", ".tsv", ".log", ".txt",
		".pdf",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the Cohen catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	if ext == ".cohen" || ext == ".cnt" {
		return true
	}
	for _, tok := range []string{
		"cohen",
		"profile", "session_token", "session-token",
		"oauth_token", "oauth-token", "refresh_token",
		"suscripcion", "suscripción",
		"rescate",
		"cuotaparte", "cuota_parte", "cuota-parte",
		"liquidacion", "liquidación",
		"research", "informe", "analyst",
		"saggm", "sagm",
		"fix_session", "fix-session", "fixsession",
		"trade_confirm", "trade-confirm", "tradeconfirm",
		"boleto",
		"statement", "estado_cuenta", "estado-cuenta",
		"nettrader", "net_trader", "net-trader",
		"mobile",
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
		if strings.Contains(n, "cohen") {
			return KindInstaller
		}
		return KindOther
	case ".cohen":
		return KindProfile
	case ".cnt":
		return KindSessionToken
	}
	switch {
	case strings.Contains(n, "oauth_token") ||
		strings.Contains(n, "oauth-token") ||
		strings.Contains(n, "refresh_token") ||
		strings.Contains(n, "refresh-token") ||
		(strings.Contains(n, "mobile") && (ext == ".json" || ext == ".xml")):
		return KindMobileOAuth
	case strings.Contains(n, "suscripcion") ||
		strings.Contains(n, "suscripción") ||
		strings.Contains(n, "subscription"):
		return KindFCISubscription
	case strings.Contains(n, "rescate") ||
		strings.Contains(n, "redemption"):
		return KindFCIRedemption
	case strings.Contains(n, "cuotaparte") ||
		strings.Contains(n, "cuota_parte") ||
		strings.Contains(n, "cuota-parte"):
		return KindCuotaparteRecord
	case strings.Contains(n, "liquidacion") ||
		strings.Contains(n, "liquidación"):
		if ext == ".pdf" {
			return KindLiquidacionPDF
		}
		return KindLiquidacionPDF
	case (strings.Contains(n, "research") ||
		strings.Contains(n, "informe") ||
		strings.Contains(n, "analyst")) && ext == ".pdf":
		return KindResearchPDF
	case strings.Contains(n, "saggm") || strings.Contains(n, "sagm"):
		return KindSAGGMConfig
	case strings.Contains(n, "fix_session") ||
		strings.Contains(n, "fix-session") ||
		strings.Contains(n, "fixsession"):
		return KindFIXSession
	case strings.Contains(n, "trade_confirm") ||
		strings.Contains(n, "trade-confirm") ||
		strings.Contains(n, "tradeconfirm") ||
		strings.Contains(n, "boleto"):
		return KindTradeConfirmation
	case strings.Contains(n, "statement") || strings.Contains(n, "estado_cuenta"):
		return KindStatement
	case strings.Contains(n, "session_token") ||
		strings.Contains(n, "session-token"):
		return KindSessionToken
	case strings.Contains(n, "cohen") && strings.Contains(n, "profile"):
		return KindProfile
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

// IsCredentialKind reports whether the kind carries PII /
// credential material subject to the exposure rollup.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindProfile, KindSessionToken, KindMobileOAuth,
		KindFCISubscription, KindFCIRedemption, KindCuotaparteRecord,
		KindLiquidacionPDF, KindResearchPDF,
		KindSAGGMConfig, KindFIXSession,
		KindTradeConfirmation, KindStatement:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans. Caller populates scalar
// fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.ClienteCuitPrefix != "" {
		r.HasClienteCuit = true
	}
	if r.CuentaComitente != "" {
		r.HasCuentaComitente = true
	}
	switch r.ArtifactKind {
	case KindMobileOAuth:
		r.HasOAuthRefreshToken = true
	case KindFCISubscription:
		r.HasFCISubscription = true
	case KindFCIRedemption:
		r.HasFCIRedemption = true
	case KindCuotaparteRecord:
		r.HasCuotaparteRecord = true
	case KindLiquidacionPDF:
		r.HasLiquidacionPDF = true
	case KindResearchPDF:
		r.HasResearchPDF = true
	case KindSAGGMConfig:
		r.HasSAGGMBackoffice = true
	case KindFIXSession:
		r.HasFIXSession = true
	case KindProfile, KindSessionToken, KindTradeConfirmation,
		KindStatement, KindInstaller, KindOther, KindUnknown:
		// No auto-flag for these kinds — their booleans are
		// set elsewhere (parser, cuotaparte threshold, etc.).
	}
	if r.CuotaparteCount >= InstitutionalCuotaparteThreshold {
		r.HasInstitutionalClass = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	credSignal := r.HasPasswordInProfile || r.HasOAuthRefreshToken ||
		r.HasFCISubscription || r.HasFCIRedemption ||
		r.HasLiquidacionPDF || r.HasSAGGMBackoffice ||
		r.HasFIXSession || r.HasClienteCuit
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
		return rs[i].PeriodYYYYMM < rs[j].PeriodYYYYMM
	})
}
