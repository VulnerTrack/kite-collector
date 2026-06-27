// Package winargpsp audits AR Payment-System-Processor (PSP /
// PSPCP = Proveedores de Servicios de Pago que Ofrecen Cuentas
// de Pago) artifact files cached on relationship-manager,
// chargeback-officer, aml-officer, network-engineer, and
// back-office workstations at Banelco, Link, Prisma Medios de
// Pago, Mercado Pago, Ualá, Modo, Naranja X, Personal Pay,
// Cuenta DNI BAPRO, Brubank, Lemon, Nubi, Belo.
//
// Regulated under BCRA Com. A 7780 (PSPCP/PSPOL) + 8005 (cyber)
// + 7153 (QR interoperable) + 4609 (Sistema Nacional Pagos) +
// 7916 (riesgo) + 7724 (MULC) + AFIP RG 4636 (VEP) + 4040
// (régimen PSPCP) + UIF Res. 76/2019 + 21/2018 + Ley 25.246 +
// 25.326 + 26.831 art.117 + 27.401 + 27.265 + Decreto 27/2018
// (DEBIN).
//
// Distinct from prior iters because the shape is **payment-rail
// back-office** — DEBIN batch = mass account-takeover targeting,
// CVU/CBU resolution log = reverse-lookup attack enabling
// alias-validation + bulk-DEBIN, QR interoperable = QR replay /
// phishing-QR target, ECHEQ = cheque cloning enablement, PIX-AR
// = instant-fraud window, Compe clearing = interbank liquidity
// intel, merchant onboarding = PSPCP customer DB (high-value
// PII), POS acquirer = terminal-spoofing target.
//
// Read-only by intent. (Project guideline 4.2.)
package winargpsp

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

const (
	MaxRows        = 16384
	MaxFileBytes   = 16 << 20
	RecentlyWindow = 90 * 24 * time.Hour
)

// LargeBatchValueARSThreshold — > 1B ARS aggregate batch value
// flags large-batch rollup. 1B ARS ≈ 1M USD wholesale and
// represents a noteworthy single-batch payment flow.
const LargeBatchValueARSThreshold = 1_000_000_000

// ArtifactKind pinned to host_arg_psp.artifact_kind.
type ArtifactKind string

const (
	KindDebinBatch         ArtifactKind = "psp-debin-batch"
	KindCVUCBUResolution   ArtifactKind = "psp-cvu-cbu-resolution"
	KindQRInteroperable    ArtifactKind = "psp-qr-interoperable"
	KindEcheqIssuance      ArtifactKind = "psp-echeq-issuance"
	KindPixARBatch         ArtifactKind = "psp-pix-ar-batch"
	KindCompeClearing      ArtifactKind = "psp-compe-clearing"
	KindPagoMisCuentas     ArtifactKind = "psp-pago-mis-cuentas"
	KindVEPAFIP            ArtifactKind = "psp-vep-afip"
	KindPOSAcquirerBatch   ArtifactKind = "psp-pos-acquirer-batch"
	KindCashOutBatch       ArtifactKind = "psp-cash-out-batch"
	KindMerchantOnboarding ArtifactKind = "psp-merchant-onboarding"
	KindBCRAInfoRegimen    ArtifactKind = "psp-bcra-info-regimen"
	KindConfig             ArtifactKind = "psp-config"
	KindCredentials        ArtifactKind = "psp-credentials"
	KindInstaller          ArtifactKind = "psp-installer"
	KindOther              ArtifactKind = "other"
	KindUnknown            ArtifactKind = "unknown"
)

// PSPNetwork pinned to host_arg_psp.psp_network.
type PSPNetwork string

const (
	NetworkBanelco        PSPNetwork = "banelco"
	NetworkLink           PSPNetwork = "link"
	NetworkPrisma         PSPNetwork = "prisma"
	NetworkMercadoPago    PSPNetwork = "mercado-pago"
	NetworkUala           PSPNetwork = "uala"
	NetworkModo           PSPNetwork = "modo"
	NetworkNaranjaX       PSPNetwork = "naranja-x"
	NetworkPersonalPay    PSPNetwork = "personal-pay"
	NetworkCuentaDNIBAPRO PSPNetwork = "cuenta-dni-bapro"
	NetworkBrubank        PSPNetwork = "brubank"
	NetworkLemon          PSPNetwork = "lemon"
	NetworkNubi           PSPNetwork = "nubi"
	NetworkBelo           PSPNetwork = "belo"
	NetworkCustom         PSPNetwork = "custom"
	NetworkNone           PSPNetwork = "none"
	NetworkUnknown        PSPNetwork = "unknown"
)

// SettlementRail pinned to host_arg_psp.settlement_rail.
type SettlementRail string

const (
	RailCompe      SettlementRail = "compe"
	RailMEP        SettlementRail = "mep"
	RailCOELSA     SettlementRail = "coelsa"
	RailDEBIN      SettlementRail = "debin"
	RailTransfer30 SettlementRail = "transfer-3-0"
	RailPIXAR      SettlementRail = "pix-ar"
	RailCustom     SettlementRail = "custom"
	RailNone       SettlementRail = "none"
	RailUnknown    SettlementRail = "unknown"
)

// PSPRole pinned to host_arg_psp.psp_role.
type PSPRole string

const (
	RoleRelationshipManager PSPRole = "relationship-manager"
	RoleChargebackOfficer   PSPRole = "chargeback-officer"
	RoleAMLOfficer          PSPRole = "aml-officer"
	RoleBackOffice          PSPRole = "back-office"
	RoleMiddleOffice        PSPRole = "middle-office"
	RoleComplianceOfficer   PSPRole = "compliance-officer"
	RoleNetworkEngineer     PSPRole = "network-engineer"
	RoleCCO                 PSPRole = "cco"
	RoleAPI                 PSPRole = "api"
	RoleOther               PSPRole = "other"
	RoleUnknown             PSPRole = "unknown"
)

// TransactionType pinned to host_arg_psp.transaction_type.
type TransactionType string

const (
	TxP2P            TransactionType = "p2p"
	TxP2M            TransactionType = "p2m"
	TxM2P            TransactionType = "m2p"
	TxB2B            TransactionType = "b2b"
	TxPayroll        TransactionType = "payroll"
	TxVEPAFIP        TransactionType = "vep-afip"
	TxTaxCollection  TransactionType = "tax-collection"
	TxUtilityPayment TransactionType = "utility-payment"
	TxSubscription   TransactionType = "subscription"
	TxCustom         TransactionType = "custom"
	TxNone           TransactionType = "none"
	TxUnknown        TransactionType = "unknown"
)

// Row mirrors host_arg_psp column shape.
type Row struct {
	FilePath                    string          `json:"file_path"`
	FileHash                    string          `json:"file_hash"`
	UserProfile                 string          `json:"user_profile,omitempty"`
	ArtifactKind                ArtifactKind    `json:"artifact_kind"`
	PSPNetwork                  PSPNetwork      `json:"psp_network"`
	SettlementRail              SettlementRail  `json:"settlement_rail,omitempty"`
	PSPRole                     PSPRole         `json:"psp_role"`
	TransactionType             TransactionType `json:"transaction_type,omitempty"`
	ReportingPeriod             string          `json:"reporting_period,omitempty"`
	PSPCuitPrefix               string          `json:"psp_cuit_prefix,omitempty"`
	PSPCuitSuffix4              string          `json:"psp_cuit_suffix4,omitempty"`
	CustomerCVUHash             string          `json:"customer_cvu_hash,omitempty"`
	MerchantCuitPrefix          string          `json:"merchant_cuit_prefix,omitempty"`
	MerchantCuitSuffix4         string          `json:"merchant_cuit_suffix4,omitempty"`
	BatchID                     string          `json:"batch_id,omitempty"`
	TransactionCount            int64           `json:"transaction_count,omitempty"`
	CustomerCount               int64           `json:"customer_count,omitempty"`
	MerchantCount               int64           `json:"merchant_count,omitempty"`
	BatchValueARS               int64           `json:"batch_value_ars,omitempty"`
	ChargebackCount             int64           `json:"chargeback_count,omitempty"`
	FileOwnerUID                int             `json:"file_owner_uid,omitempty"`
	FileMode                    int             `json:"file_mode,omitempty"`
	FileSize                    int64           `json:"file_size,omitempty"`
	HasPasswordInConfig         bool            `json:"has_password_in_config"`
	HasDebinBatch               bool            `json:"has_debin_batch"`
	HasCVUCBUResolution         bool            `json:"has_cvu_cbu_resolution"`
	HasQRInteroperable          bool            `json:"has_qr_interoperable"`
	HasEcheqIssuance            bool            `json:"has_echeq_issuance"`
	HasPixARBatch               bool            `json:"has_pix_ar_batch"`
	HasCompeClearing            bool            `json:"has_compe_clearing"`
	HasPagoMisCuentas           bool            `json:"has_pago_mis_cuentas"`
	HasVEPAFIP                  bool            `json:"has_vep_afip"`
	HasPOSAcquirerBatch         bool            `json:"has_pos_acquirer_batch"`
	HasCashOutBatch             bool            `json:"has_cash_out_batch"`
	HasMerchantOnboarding       bool            `json:"has_merchant_onboarding"`
	HasBCRAInfoRegimen          bool            `json:"has_bcra_info_regimen"`
	HasPSPCuit                  bool            `json:"has_psp_cuit"`
	HasCustomerCVU              bool            `json:"has_customer_cvu"`
	HasMerchantCuit             bool            `json:"has_merchant_cuit"`
	HasLargeBatchValue          bool            `json:"has_large_batch_value"`
	IsRecent                    bool            `json:"is_recent"`
	IsWorldReadable             bool            `json:"is_world_readable"`
	IsGroupReadable             bool            `json:"is_group_readable"`
	IsCredentialExposureRisk    bool            `json:"is_credential_exposure_risk"`
	IsPaymentPIIRisk            bool            `json:"is_payment_pii_risk"`
	IsAMLTypologyLeak           bool            `json:"is_aml_typology_leak"`
	IsSettlementChainDisclosure bool            `json:"is_settlement_chain_disclosure"`
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

// DefaultInstallRoots is the curated PSP install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\PSP`,
		`C:\Banelco`,
		`C:\Link`,
		`C:\Prisma`,
		`C:\MercadoPago`,
		`C:\Program Files\PSP`,
		"/opt/psp",
		"/opt/banelco",
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

// UserPSPDirs is the curated per-user relative path set.
func UserPSPDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "PSP"},
		{"AppData", "Roaming", "Banelco"},
		{"AppData", "Roaming", "Link"},
		{"AppData", "Roaming", "MercadoPago"},
		{"AppData", "Local", "PSP"},
		{".config", "psp"},
		{".psp"},
		{"Documents", "PSP"},
		{"Documents", "Pagos"},
		{"Documents", "Cobros"},
		{"psp"},
		{"pagos"},
		{"cobros"},
		{"merchants"},
		{"settlements"},
		{"Library", "Application Support", "PSP"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a PSP
// artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".json",
		".cfg", ".ini", ".conf",
		".csv", ".tsv", ".log", ".txt",
		".xlsx", ".xls", ".ods",
		".pdf", ".doc", ".docx",
		".md", ".markdown",
		".yaml", ".yml", ".toml",
		".msi", ".exe", ".pkg", ".dmg":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the PSP catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"debin_batch", "debin-batch", "debin_",
		"cvu_cbu_resolution", "cvu-cbu-resolution", "cvu_resolve",
		"qr_interoperable", "qr-interoperable", "qr_interop",
		"echeq_issuance", "echeq-issuance", "echeq_",
		"pix_ar_batch", "pix-ar-batch", "pix_ar", "pix-ar",
		"compe_clearing", "compe-clearing", "compe_batch",
		"pago_mis_cuentas", "pago-mis-cuentas", "pmc_",
		"vep_afip", "vep-afip", "vep_",
		"pos_acquirer", "pos-acquirer", "acquirer_batch",
		"cash_out_batch", "cash-out-batch", "cashout_",
		"merchant_onboarding", "merchant-onboarding", "kyc_merchant",
		"bcra_info_regimen", "bcra-info-regimen", "regimen_psp",
		"psp_config", "psp-config", "psp_",
		"banelco_", "link_", "prisma_",
		"mercado_pago", "mercado-pago", "mp_",
		"uala_", "modo_", "naranja_x", "naranja-x",
		"personal_pay", "personal-pay",
		"cuenta_dni", "cuenta-dni", "bapro_",
		"brubank_", "lemon_", "nubi_", "belo_",
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
	ext := strings.ToLower(filepath.Ext(n))
	switch ext {
	case ".msi", ".exe", ".pkg", ".dmg":
		if strings.Contains(n, "psp") || strings.Contains(n, "banelco") ||
			strings.Contains(n, "link") || strings.Contains(n, "mp_") {
			return KindInstaller
		}
		return KindOther
	}
	switch {
	case strings.Contains(n, "bcra_info_regimen") ||
		strings.Contains(n, "bcra-info-regimen") ||
		strings.Contains(n, "regimen_psp"):
		return KindBCRAInfoRegimen
	case strings.Contains(n, "merchant_onboarding") ||
		strings.Contains(n, "merchant-onboarding") ||
		strings.Contains(n, "kyc_merchant"):
		return KindMerchantOnboarding
	case strings.Contains(n, "cash_out_batch") ||
		strings.Contains(n, "cash-out-batch") ||
		strings.HasPrefix(n, "cashout_"):
		return KindCashOutBatch
	case strings.Contains(n, "pos_acquirer") ||
		strings.Contains(n, "pos-acquirer") ||
		strings.Contains(n, "acquirer_batch"):
		return KindPOSAcquirerBatch
	case strings.Contains(n, "vep_afip") ||
		strings.Contains(n, "vep-afip") ||
		strings.HasPrefix(n, "vep_"):
		return KindVEPAFIP
	case strings.Contains(n, "pago_mis_cuentas") ||
		strings.Contains(n, "pago-mis-cuentas") ||
		strings.HasPrefix(n, "pmc_"):
		return KindPagoMisCuentas
	case strings.Contains(n, "compe_clearing") ||
		strings.Contains(n, "compe-clearing") ||
		strings.Contains(n, "compe_batch"):
		return KindCompeClearing
	case strings.Contains(n, "pix_ar_batch") ||
		strings.Contains(n, "pix-ar-batch") ||
		strings.Contains(n, "pix_ar") ||
		strings.Contains(n, "pix-ar"):
		return KindPixARBatch
	case strings.Contains(n, "echeq_issuance") ||
		strings.Contains(n, "echeq-issuance") ||
		strings.HasPrefix(n, "echeq_"):
		return KindEcheqIssuance
	case strings.Contains(n, "qr_interoperable") ||
		strings.Contains(n, "qr-interoperable") ||
		strings.Contains(n, "qr_interop"):
		return KindQRInteroperable
	case strings.Contains(n, "cvu_cbu_resolution") ||
		strings.Contains(n, "cvu-cbu-resolution") ||
		strings.Contains(n, "cvu_resolve"):
		return KindCVUCBUResolution
	case strings.Contains(n, "debin_batch") ||
		strings.Contains(n, "debin-batch") ||
		strings.HasPrefix(n, "debin_"):
		return KindDebinBatch
	case n == "credentials.json" || n == "credentials.yaml" ||
		n == "credentials.yml" || strings.HasPrefix(n, "credentials"):
		return KindCredentials
	case strings.Contains(n, "psp") && strings.Contains(n, "config"):
		return KindConfig
	}
	return KindOther
}

// PSPNetworkFromName detects PSP network from filename.
func PSPNetworkFromName(name string) PSPNetwork {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.HasPrefix(n, "banelco_") || strings.Contains(n, "_banelco_"):
		return NetworkBanelco
	case strings.HasPrefix(n, "link_") || strings.Contains(n, "_link_"):
		return NetworkLink
	case strings.HasPrefix(n, "prisma_") || strings.Contains(n, "_prisma_"):
		return NetworkPrisma
	case strings.Contains(n, "mercado_pago") ||
		strings.Contains(n, "mercado-pago") ||
		strings.HasPrefix(n, "mp_"):
		return NetworkMercadoPago
	case strings.HasPrefix(n, "uala_") || strings.Contains(n, "_uala_"):
		return NetworkUala
	case strings.HasPrefix(n, "modo_") || strings.Contains(n, "_modo_"):
		return NetworkModo
	case strings.Contains(n, "naranja_x") || strings.Contains(n, "naranja-x"):
		return NetworkNaranjaX
	case strings.Contains(n, "personal_pay") || strings.Contains(n, "personal-pay"):
		return NetworkPersonalPay
	case strings.Contains(n, "cuenta_dni") || strings.Contains(n, "cuenta-dni") ||
		strings.HasPrefix(n, "bapro_"):
		return NetworkCuentaDNIBAPRO
	case strings.HasPrefix(n, "brubank_") || strings.Contains(n, "_brubank_"):
		return NetworkBrubank
	case strings.HasPrefix(n, "lemon_") || strings.Contains(n, "_lemon_"):
		return NetworkLemon
	case strings.HasPrefix(n, "nubi_") || strings.Contains(n, "_nubi_"):
		return NetworkNubi
	case strings.HasPrefix(n, "belo_") || strings.Contains(n, "_belo_"):
		return NetworkBelo
	}
	return NetworkUnknown
}

// CuitEntityOnlyPrefixes is the entity-only subset.
func CuitEntityOnlyPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidCuitEntityOnlyPrefix reports prefix membership.
func IsValidCuitEntityOnlyPrefix(p string) bool {
	for _, v := range CuitEntityOnlyPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// CuitAllPrefixes is the broader set (individuals + entities)
// because merchants may be unincorporated.
func CuitAllPrefixes() []string {
	return []string{"20", "23", "24", "27", "30", "33", "34"}
}

// IsValidCuitAllPrefix reports membership in the broader set.
func IsValidCuitAllPrefix(p string) bool {
	for _, v := range CuitAllPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// CuitEntityOnlyFingerprint extracts PSP-entity CUIT.
func CuitEntityOnlyFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitEntityOnlyPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// CuitAnyFingerprint extracts merchant CUIT (individuals OK).
func CuitAnyFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidCuitAllPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// PeriodFromFilename extracts YYYYMM or YYYY from a filename.
func PeriodFromFilename(name string) string {
	if m := regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1] + m[2]
	}
	if m := regexp.MustCompile(`(20\d{2})`).
		FindStringSubmatch(filepath.Base(name)); m != nil {
		return m[1]
	}
	return ""
}

// IsCredentialKind reports whether the kind carries PII /
// credential material.
func IsCredentialKind(k ArtifactKind) bool {
	switch k {
	case KindDebinBatch, KindCVUCBUResolution,
		KindQRInteroperable, KindEcheqIssuance,
		KindPixARBatch, KindCompeClearing,
		KindPagoMisCuentas, KindVEPAFIP,
		KindPOSAcquirerBatch, KindCashOutBatch,
		KindMerchantOnboarding, KindBCRAInfoRegimen,
		KindConfig, KindCredentials:
		return true
	case KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsPaymentPIIKind reports whether the kind carries customer/
// merchant CVU/CBU + ID exposure material.
func IsPaymentPIIKind(k ArtifactKind) bool {
	switch k {
	case KindDebinBatch, KindCVUCBUResolution,
		KindMerchantOnboarding, KindCashOutBatch:
		return true
	case KindQRInteroperable, KindEcheqIssuance,
		KindPixARBatch, KindCompeClearing,
		KindPagoMisCuentas, KindVEPAFIP,
		KindPOSAcquirerBatch, KindBCRAInfoRegimen,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsAMLTypologyKind reports whether the kind carries AML
// typology / régimen-informativo / STR-equivalent material.
func IsAMLTypologyKind(k ArtifactKind) bool {
	switch k {
	case KindBCRAInfoRegimen, KindMerchantOnboarding:
		return true
	case KindDebinBatch, KindCVUCBUResolution,
		KindQRInteroperable, KindEcheqIssuance,
		KindPixARBatch, KindCompeClearing,
		KindPagoMisCuentas, KindVEPAFIP,
		KindPOSAcquirerBatch, KindCashOutBatch,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsSettlementChainKind reports whether the kind reveals
// settlement-rail timing + counterparty material.
func IsSettlementChainKind(k ArtifactKind) bool {
	switch k {
	case KindCompeClearing, KindPixARBatch,
		KindEcheqIssuance, KindPOSAcquirerBatch:
		return true
	case KindDebinBatch, KindCVUCBUResolution,
		KindQRInteroperable,
		KindPagoMisCuentas, KindVEPAFIP,
		KindCashOutBatch, KindMerchantOnboarding,
		KindBCRAInfoRegimen,
		KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// AnnotateSecurity sets derived booleans.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.PSPCuitPrefix != "" {
		r.HasPSPCuit = true
	}
	if r.CustomerCVUHash != "" {
		r.HasCustomerCVU = true
	}
	if r.MerchantCuitPrefix != "" {
		r.HasMerchantCuit = true
	}
	switch r.ArtifactKind {
	case KindDebinBatch:
		r.HasDebinBatch = true
	case KindCVUCBUResolution:
		r.HasCVUCBUResolution = true
	case KindQRInteroperable:
		r.HasQRInteroperable = true
	case KindEcheqIssuance:
		r.HasEcheqIssuance = true
	case KindPixARBatch:
		r.HasPixARBatch = true
	case KindCompeClearing:
		r.HasCompeClearing = true
	case KindPagoMisCuentas:
		r.HasPagoMisCuentas = true
	case KindVEPAFIP:
		r.HasVEPAFIP = true
	case KindPOSAcquirerBatch:
		r.HasPOSAcquirerBatch = true
	case KindCashOutBatch:
		r.HasCashOutBatch = true
	case KindMerchantOnboarding:
		r.HasMerchantOnboarding = true
	case KindBCRAInfoRegimen:
		r.HasBCRAInfoRegimen = true
	case KindConfig, KindCredentials,
		KindInstaller, KindOther, KindUnknown:
		// No auto-flag.
	}
	if r.BatchValueARS >= LargeBatchValueARSThreshold {
		r.HasLargeBatchValue = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	if readable && r.HasPasswordInConfig && IsCredentialKind(r.ArtifactKind) {
		r.IsCredentialExposureRisk = true
	}
	if readable && IsPaymentPIIKind(r.ArtifactKind) {
		r.IsPaymentPIIRisk = true
	}
	if readable && IsAMLTypologyKind(r.ArtifactKind) {
		r.IsAMLTypologyLeak = true
	}
	if readable && IsSettlementChainKind(r.ArtifactKind) {
		r.IsSettlementChainDisclosure = true
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
		return rs[i].ReportingPeriod < rs[j].ReportingPeriod
	})
}
