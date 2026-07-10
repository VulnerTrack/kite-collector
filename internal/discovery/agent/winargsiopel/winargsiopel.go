// Package winargsiopel audits SIOPEL trading-terminal files
// cached on Argentine bank, broker, prop-desk, and back-
// office workstations across Windows, Linux, and macOS.
//
// SIOPEL (Sistema Integrado de Operaciones Electrónicas) is
// the official trading terminal of the MAE (Mercado Abierto
// Electrónico). It is also white-labeled for MAV and BCRA
// forex auctions. Every Argentine bank trading OTC fixed-
// income, FX, Leliq/Lecap, sovereign bonds, or BCRA-managed
// instruments runs SIOPEL on dealer + back-office desks.
//
// **The OTC-terminal layer.** Distinct from:
//
//   - iter 107 winargcnvalyc      — ALYC broker disclosure
//   - iter 108 winalgotrading     — FIX/EA technical layer
//   - iter 109 winargmatbarofex   — derivatives positions
//   - iter 110 winargfci          — FCI mutual-fund layer
//   - iter 111 winargpymebursatil — PyME instrument-level
//   - iter 113 winargfix          — wire-protocol session logs
//   - iter 117 winargcvsa         — CVSA custody layer
//
// Headline finding shapes:
//
//   - `has_password_in_config=1` — siopel.ini carries
//     Password=/Clave=/PasswordOp= cleartext.
//   - `has_caucion_repo=1` — caución rueda entry > 30 days
//     tenor (regulatory cap).
//   - `has_mep_ccl_arbitrage=1` — paired MEP buy + CCL sell
//     in the same session window.
//   - `is_after_hours=1` — concertación outside venue hours.
//   - `is_credential_exposure_risk=1` — readable file +
//     operator CUIT + (password OR trade body OR concertación).
//
// Read-only by intent. (Project guideline 4.2.)
package winargsiopel

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

// MaxFileBytes bounds per-file read. SIOPEL rueda XML files
// rarely exceed 8 MiB; session logs can grow but are read
// in full to scan for concertación markers.
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff (90d).
const RecentlyWindow = 90 * 24 * time.Hour

// CaucionMaxTenorDaysCap — BCRA Com. A regulatory cap for
// caución bursátil tenor in days. Entries above flag.
const CaucionMaxTenorDaysCap = 30

// VenueOpenHourART — MAE concertación window opens 10:00 ART
// (UTC-3). Slightly earlier (09:30) for MAV — we pick the
// narrower MAE window as the after-hours floor.
const VenueOpenHourART = 10

// VenueCloseHourART — MAE concertación window closes 15:00
// ART. Anything past 15:00 ART flags after-hours.
const VenueCloseHourART = 15

// ArtifactKind pinned to host_arg_siopel.artifact_kind.
type ArtifactKind string

const (
	KindSIOPELConfig     ArtifactKind = "siopel-config"
	KindRuedaData        ArtifactKind = "siopel-rueda-data"
	KindSessionLog       ArtifactKind = "siopel-session-log"
	KindOperatorProfile  ArtifactKind = "siopel-operator-profile"
	KindPrecierre        ArtifactKind = "siopel-precierre"
	KindSIOPELCache      ArtifactKind = "siopel-cache"
	KindMAEClearExport   ArtifactKind = "maeclear-export"
	KindMAEBCRAForexAuct ArtifactKind = "mae-bcra-forex"
	KindSIOPELInstaller  ArtifactKind = "siopel-installer"
	KindOther            ArtifactKind = "other"
	KindUnknown          ArtifactKind = "unknown"
)

// Venue pinned to host_arg_siopel.venue.
type Venue string

const (
	VenueMAE     Venue = "mae"
	VenueMAV     Venue = "mav"
	VenueBCRA    Venue = "bcra"
	VenueOther   Venue = "other"
	VenueUnknown Venue = "unknown"
)

// RuedaKind pinned to host_arg_siopel.rueda_kind.
type RuedaKind string

const (
	RuedaCambio      RuedaKind = "rueda-cambio"
	RuedaMEP         RuedaKind = "rueda-mep"
	RuedaBono        RuedaKind = "rueda-bono"
	RuedaLeliq       RuedaKind = "rueda-leliq"
	RuedaRofexBridge RuedaKind = "rueda-rofex-bridge"
	RuedaCaucion     RuedaKind = "rueda-caucion"
	RuedaCheque      RuedaKind = "rueda-cheque"
	RuedaLetes       RuedaKind = "rueda-letes"
	RuedaPMD         RuedaKind = "rueda-pmd"
	RuedaOther       RuedaKind = "other"
	RuedaUnknown     RuedaKind = "unknown"
)

// Row mirrors host_arg_siopel column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	Venue                    Venue        `json:"venue"`
	RuedaKind                RuedaKind    `json:"rueda_kind"`
	OperatorMatricula        string       `json:"operator_matricula,omitempty"`
	OperatorCuitPrefix       string       `json:"operator_cuit_prefix,omitempty"`
	OperatorCuitSuffix4      string       `json:"operator_cuit_suffix4,omitempty"`
	DealerCode               string       `json:"dealer_code,omitempty"`
	ClienteCuitPrefix        string       `json:"cliente_cuit_prefix,omitempty"`
	ClienteCuitSuffix4       string       `json:"cliente_cuit_suffix4,omitempty"`
	SessionFirstSeen         string       `json:"session_first_seen,omitempty"`
	SessionLastSeen          string       `json:"session_last_seen,omitempty"`
	PeriodYYYYMM             string       `json:"period_yyyymm,omitempty"`
	TradeCount               int64        `json:"trade_count,omitempty"`
	ConcertacionCount        int64        `json:"concertacion_count,omitempty"`
	BajaCount                int64        `json:"baja_count,omitempty"`
	MaxNotionalARSCents      int64        `json:"max_notional_ars_cents,omitempty"`
	CaucionMaxTenorDays      int          `json:"caucion_max_tenor_days,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasPasswordInConfig      bool         `json:"has_password_in_config"`
	HasCaucionRepo           bool         `json:"has_caucion_repo"`
	HasMEPCCLArbitrage       bool         `json:"has_mep_ccl_arbitrage"`
	HasConcertacion          bool         `json:"has_concertacion"`
	IsAfterHours             bool         `json:"is_after_hours"`
	HasOperatorCuit          bool         `json:"has_operator_cuit"`
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

// DefaultInstallRoots is the curated SIOPEL install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\SIOPEL`,
		`C:\Siopel`,
		`C:\Program Files\SIOPEL`,
		`C:\Program Files (x86)\SIOPEL`,
		`C:\MAE\SIOPEL`,
		`C:\MAE\MAEClear`,
		`C:\MAEClear`,
		`C:\MAV\SIOPEL`,
		`C:\BCRA\SIOPEL`,
		`/opt/siopel`,
		`/opt/mae/siopel`,
		`/srv/mae/siopel`,
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

// UserSIOPELDirs is the curated per-user relative path set.
func UserSIOPELDirs() [][]string {
	return [][]string{
		{"AppData", "Roaming", "SIOPEL"},
		{"AppData", "Local", "SIOPEL"},
		{"AppData", "Roaming", "MAE", "SIOPEL"},
		{"AppData", "Roaming", "MAEClear"},
		{"Documents", "SIOPEL"},
		{"Documents", "MAE"},
		{"Documents", "MAEClear"},
		{"Documents", "Trading", "SIOPEL"},
		{"Descargas"},
		{"Downloads"},
	}
}

// IsCandidateExt reports whether the extension carries a
// SIOPEL artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".ini", ".cfg", ".conf",
		".xml", ".csv", ".tsv",
		".dat", ".usr",
		".log", ".txt",
		".msi", ".exe":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the SIOPEL catalogue (after passing the extension gate).
//
// SIOPEL workstations tend to have generic file names; we
// require either:
//  1. an explicit SIOPEL / MAE / MAEClear marker, or
//  2. one of the canonical rueda/sesion/operadores tokens.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(n))
	// .usr is a SIOPEL-only operator-profile extension.
	if ext == ".usr" {
		return true
	}
	for _, tok := range []string{
		"siopel", "maeclear", "mae_clear", "mae-clear",
		"rueda_", "rueda-",
		"sesion_", "sesion-",
		"operador", "operadores",
		"precierre", "pre_cierre", "pre-cierre",
		"concertacion", "concertaci",
		"bcra_subasta", "bcra-subasta", "subastabcra",
		"caucion_", "caucion-",
		"mep_ccl", "mep-ccl",
		"leliq", "lecap",
		"_mae.", "_mav.", "_bcra.",
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
	case ".usr":
		return KindOperatorProfile
	case ".msi", ".exe":
		if strings.Contains(n, "siopel") {
			return KindSIOPELInstaller
		}
		return KindOther
	case ".dat":
		if strings.Contains(n, "rueda") {
			return KindRuedaData
		}
		return KindSIOPELCache
	}
	switch {
	case strings.Contains(n, "siopel") &&
		(ext == ".ini" || ext == ".cfg" || ext == ".conf"):
		return KindSIOPELConfig
	case strings.Contains(n, "rueda"):
		return KindRuedaData
	case strings.Contains(n, "concertacion") ||
		strings.Contains(n, "concertaci"):
		return KindRuedaData
	case strings.Contains(n, "sesion") && ext == ".log":
		return KindSessionLog
	case strings.Contains(n, "siopel") && ext == ".log":
		return KindSessionLog
	case strings.Contains(n, "precierre") ||
		strings.Contains(n, "pre_cierre") ||
		strings.Contains(n, "pre-cierre"):
		return KindPrecierre
	case strings.Contains(n, "maeclear") ||
		strings.Contains(n, "mae_clear") ||
		strings.Contains(n, "mae-clear"):
		return KindMAEClearExport
	case strings.Contains(n, "bcra_subasta") ||
		strings.Contains(n, "bcra-subasta") ||
		strings.Contains(n, "subastabcra") ||
		(strings.Contains(n, "bcra") && strings.Contains(n, "forex")):
		return KindMAEBCRAForexAuct
	case strings.Contains(n, "operador"):
		return KindOperatorProfile
	}
	return KindOther
}

// VenueFromPath classifies the venue from path tokens.
// MAEClear is post-trade for MAE → maps to mae.
// BCRA path / filename → bcra. MAV path / filename → mav.
//
// On Linux CI, Windows-style paths still need to classify
// correctly, so we normalize backslashes to forward-slashes
// before token matching.
func VenueFromPath(path string) Venue {
	if path == "" {
		return VenueUnknown
	}
	lower := strings.ToLower(
		strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"),
	)
	switch {
	case strings.Contains(lower, "bcra_subasta") ||
		strings.Contains(lower, "bcra-subasta") ||
		strings.Contains(lower, "subastabcra") ||
		strings.Contains(lower, "/bcra/"):
		return VenueBCRA
	case strings.Contains(lower, "/mav/") ||
		strings.Contains(lower, "_mav.") ||
		strings.Contains(lower, "-mav."):
		return VenueMAV
	case strings.Contains(lower, "maeclear") ||
		strings.Contains(lower, "mae_clear") ||
		strings.Contains(lower, "mae-clear") ||
		strings.Contains(lower, "/mae/") ||
		strings.Contains(lower, "siopel"):
		return VenueMAE
	}
	return VenueUnknown
}

// RuedaKindFromName classifies a rueda filename / token.
func RuedaKindFromName(name string) RuedaKind {
	if strings.TrimSpace(name) == "" {
		return RuedaUnknown
	}
	n := strings.ToLower(filepath.Base(name))
	switch {
	case strings.Contains(n, "rueda_cambio") ||
		strings.Contains(n, "rueda-cambio") ||
		strings.Contains(n, "ruedacambio") ||
		strings.Contains(n, "_cambio.") ||
		strings.Contains(n, "_fx."):
		return RuedaCambio
	case strings.Contains(n, "mep_ccl") ||
		strings.Contains(n, "mep-ccl") ||
		strings.Contains(n, "_mep_") ||
		strings.Contains(n, "_mep.") ||
		strings.Contains(n, "_ccl_") ||
		strings.Contains(n, "_ccl.") ||
		strings.HasPrefix(n, "mep_") ||
		strings.HasPrefix(n, "ccl_"):
		return RuedaMEP
	case strings.Contains(n, "leliq"):
		return RuedaLeliq
	case strings.Contains(n, "letes"):
		return RuedaLetes
	case strings.Contains(n, "caucion"):
		return RuedaCaucion
	case strings.Contains(n, "cheque"):
		return RuedaCheque
	case strings.Contains(n, "rofex") ||
		strings.Contains(n, "matba"):
		return RuedaRofexBridge
	case strings.Contains(n, "_pmd") ||
		strings.Contains(n, "-pmd") ||
		strings.Contains(n, "pyme") ||
		strings.Contains(n, "pyme"):
		return RuedaPMD
	case strings.Contains(n, "bono") ||
		strings.Contains(n, "soberano") ||
		strings.Contains(n, "sovereign"):
		return RuedaBono
	}
	return RuedaUnknown
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

// IsOperatorCuitPrefix reports whether the prefix is a human-
// operator class (20/23/24/27).
func IsOperatorCuitPrefix(p string) bool {
	switch p {
	case "20", "23", "24", "27":
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

// MatriculaRE matches MAE operator matrícula in text.
var matriculaRE = regexp.MustCompile(`(?i)(?:operador|matr[íi]cula|matricula_operador|mae_matricula)[\s:#=\w\.\-]{0,30}?(\d{1,5})`)

// MatriculaFromText extracts MAE operator matrícula.
func MatriculaFromText(text string) string {
	m := matriculaRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// dealerCodeRE matches a SIOPEL/MAE dealer code: 3-5 upper-
// alpha. We only honour it when wrapped in an explicit key.
var dealerCodeRE = regexp.MustCompile(`(?i)(?:dealer[_-]?code|codigo[_-]?dealer|cod[_-]?operador)\s*[:=]\s*([A-Z]{3,5})`)

// DealerCodeFromText extracts the dealer code.
func DealerCodeFromText(text string) string {
	m := dealerCodeRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
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

// IsRuedaArtifactKind reports whether the kind carries
// rueda-level concertación data.
func IsRuedaArtifactKind(k ArtifactKind) bool {
	switch k {
	case KindRuedaData, KindPrecierre, KindMAEClearExport,
		KindMAEBCRAForexAuct:
		return true
	case KindSIOPELConfig, KindSessionLog, KindOperatorProfile,
		KindSIOPELCache, KindSIOPELInstaller, KindOther, KindUnknown:
		return false
	}
	return false
}

// IsAfterHoursStamp parses a "HH:MM" or "HH:MM:SS" token in
// ART (UTC-3) and reports whether it falls outside the venue
// hours [VenueOpenHourART, VenueCloseHourART). Sub-second
// timestamps are accepted but truncated to HH.
func IsAfterHoursStamp(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Accept patterns like "2026-06-23 16:42", "16:42:01",
	// "T16:42:01-03:00" — we only care about HH between :s.
	re := regexp.MustCompile(`(\d{1,2}):\d{2}`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	h := 0
	for _, c := range m[1] {
		h = h*10 + int(c-'0')
	}
	if h < 0 || h > 23 {
		return false
	}
	return h < VenueOpenHourART || h >= VenueCloseHourART
}

// AnnotateSecurity sets derived booleans. Caller populates
// scalar fields first.
func AnnotateSecurity(r *Row) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.OperatorCuitPrefix != "" {
		r.HasOperatorCuit = true
	}
	if r.CaucionMaxTenorDays > CaucionMaxTenorDaysCap {
		r.HasCaucionRepo = true
	}
	if r.ConcertacionCount > 0 {
		r.HasConcertacion = true
	}
	if r.SessionFirstSeen != "" && IsAfterHoursStamp(r.SessionFirstSeen) {
		r.IsAfterHours = true
	}
	if !r.IsAfterHours && r.SessionLastSeen != "" &&
		IsAfterHoursStamp(r.SessionLastSeen) {
		r.IsAfterHours = true
	}
	readable := r.IsWorldReadable || r.IsGroupReadable
	bodySignal := r.HasPasswordInConfig || r.HasConcertacion ||
		r.TradeCount > 0 || r.MaxNotionalARSCents > 0
	if readable && r.HasOperatorCuit && bodySignal {
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
