// Package winargcnvaif audits CNV AIF (Autopista de la
// Información Financiera) issuer-side filings cached on
// emisor compliance, abogado, and back-office workstations
// across Windows, Linux, and macOS.
//
// AIF carries the *issuer-disclosure* artifacts (prospectos,
// actas, designaciones, DDJJ autoridades/accionistas/
// beneficiarios finales, contratos de fideicomiso). DDJJ
// tipo 3 (beneficiarios finales ≥ 10 %) is direct PII under
// Ley 25.326 and Resolución CNV 218/2015.
//
// **Distinct from**:
//   - iter 90  winargxbrl    — XBRL financial statements
//   - iter 97  winargcnvhr   — hechos relevantes
//   - iter 107 winargcnvalyc — ALYC broker-dealer disclosure
//   - iter 110 winargfci     — FCI mutual-fund layer
//
// Headline finding shapes:
//
//   - `has_directorio_change=1` — board change declaration.
//   - `has_capital_change=1` — emisión / aumento / reducción.
//   - `has_beneficial_owner=1` — DDJJ tipo 3 BO data present.
//   - `is_active_offering=1` — prospecto vigencia covers
//     clock time (time-injectable).
//   - `is_credential_exposure_risk=1` — readable file +
//     emisor + (BO OR directorio change PII).
//
// Read-only by intent. (Project guideline 4.2.)
package winargcnvaif

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

// MaxFileBytes bounds per-file read (16 MiB — prospectos can
// be large).
const MaxFileBytes = 16 << 20

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// ArtifactKind pinned to host_arg_cnv_aif.artifact_kind.
type ArtifactKind string

const (
	KindProspectoEmision     ArtifactKind = "prospecto-emision"
	KindSuplementoProspecto  ArtifactKind = "suplemento-prospecto"
	KindActaAsamblea         ArtifactKind = "acta-asamblea"
	KindDesignacionDirect    ArtifactKind = "designacion-directorio"
	KindConvocatoriaAsamblea ArtifactKind = "convocatoria-asamblea"
	KindDDJJAutoridades      ArtifactKind = "ddjj-autoridades"
	KindDDJJAccionistas      ArtifactKind = "ddjj-accionistas"
	KindDDJJBeneficiarios    ArtifactKind = "ddjj-beneficiarios"
	KindContratoFideicomiso  ArtifactKind = "contrato-fideicomiso"
	KindReglamentoGestion    ArtifactKind = "reglamento-gestion"
	KindAdenda               ArtifactKind = "adenda"
	KindOther                ArtifactKind = "other"
	KindUnknown              ArtifactKind = "unknown"
)

// TipoEmision pinned to host_arg_cnv_aif.tipo_emision.
type TipoEmision string

const (
	TipoONCorporativa TipoEmision = "on-corporativa"
	TipoFCI           TipoEmision = "fci"
	TipoFideicomiso   TipoEmision = "fideicomiso"
	TipoAcciones      TipoEmision = "acciones"
	TipoPagare        TipoEmision = "pagare"
	TipoCEDEAR        TipoEmision = "cedear"
	TipoOther         TipoEmision = "other"
	TipoUnknown       TipoEmision = "unknown"
)

// Row mirrors host_arg_cnv_aif' column shape.
type Row struct {
	FilePath                 string       `json:"file_path"`
	FileHash                 string       `json:"file_hash"`
	UserProfile              string       `json:"user_profile,omitempty"`
	ArtifactKind             ArtifactKind `json:"artifact_kind"`
	EmisorCuitPrefix         string       `json:"emisor_cuit_prefix,omitempty"`
	EmisorCuitSuffix4        string       `json:"emisor_cuit_suffix4,omitempty"`
	EmisorTicker             string       `json:"emisor_ticker,omitempty"`
	DocumentoAIFID           string       `json:"documento_aif_id,omitempty"`
	TipoEmision              TipoEmision  `json:"tipo_emision"`
	FechaAprobacion          string       `json:"fecha_aprobacion,omitempty"`
	VigenciaDesde            string       `json:"vigencia_desde,omitempty"`
	VigenciaHasta            string       `json:"vigencia_hasta,omitempty"`
	MontoEmisionARSCents     int64        `json:"monto_emision_ars_cents,omitempty"`
	MontoEmisionUSDCents     int64        `json:"monto_emision_usd_cents,omitempty"`
	BeneficialOwnerCount     int64        `json:"beneficial_owner_count,omitempty"`
	FileOwnerUID             int          `json:"file_owner_uid,omitempty"`
	FileMode                 int          `json:"file_mode,omitempty"`
	FileSize                 int64        `json:"file_size,omitempty"`
	HasDirectorioChange      bool         `json:"has_directorio_change"`
	HasCapitalChange         bool         `json:"has_capital_change"`
	HasBeneficialOwner       bool         `json:"has_beneficial_owner"`
	IsActiveOffering         bool         `json:"is_active_offering"`
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

// DefaultInstallRoots is the curated AIF install-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\CNV\AIF`,
		`C:\AIF`,
		`C:\Emisor\AIF`,
		`C:\Compliance\CNV`,
		`C:\Legales\AIF`,
		`/opt/cnv/aif`,
		`/var/lib/cnv/aif`,
		`/srv/aif`,
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

// UserAIFDirs is the curated per-user relative path set.
func UserAIFDirs() [][]string {
	return [][]string{
		{"Documents", "CNV", "AIF"},
		{"Documents", "AIF"},
		{"Documents", "Compliance", "AIF"},
		{"Documents", "Legales", "AIF"},
		{"Documents", "Emisor", "AIF"},
		{"AppData", "Local", "CNV", "AIF"},
		{"AppData", "Roaming", "CNV", "AIF"},
	}
}

// IsCandidateExt reports whether the extension carries an
// AIF artifact.
func IsCandidateExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".xml", ".pdf", ".doc", ".docx", ".txt":
		return true
	}
	return false
}

// IsCandidateName reports whether a filename plausibly belongs
// to the AIF catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"prospecto_emision", "prospecto-emision",
		"prospecto_", "prospecto.",
		"suplemento_prospecto", "suplemento-prospecto",
		"acta_asamblea", "acta-asamblea",
		"designacion_directorio", "designacion-directorio",
		"convocatoria_asamblea", "convocatoria-asamblea",
		"ddjj_autoridades", "ddjj-autoridades",
		"ddjj_accionistas", "ddjj-accionistas",
		"ddjj_beneficiarios", "ddjj-beneficiarios",
		"contrato_fideicomiso", "contrato-fideicomiso",
		"reglamento_gestion", "reglamento-gestion",
		"adenda_",
		"cnv_aif", "cnv-aif",
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
	switch {
	case strings.Contains(n, "suplemento_prospecto") ||
		strings.Contains(n, "suplemento-prospecto"):
		return KindSuplementoProspecto
	case strings.Contains(n, "prospecto_emision") ||
		strings.Contains(n, "prospecto-emision") ||
		strings.Contains(n, "prospecto_") ||
		strings.Contains(n, "prospecto."):
		return KindProspectoEmision
	case strings.Contains(n, "ddjj_autoridades") ||
		strings.Contains(n, "ddjj-autoridades"):
		return KindDDJJAutoridades
	case strings.Contains(n, "ddjj_accionistas") ||
		strings.Contains(n, "ddjj-accionistas"):
		return KindDDJJAccionistas
	case strings.Contains(n, "ddjj_beneficiarios") ||
		strings.Contains(n, "ddjj-beneficiarios"):
		return KindDDJJBeneficiarios
	case strings.Contains(n, "designacion_directorio") ||
		strings.Contains(n, "designacion-directorio"):
		return KindDesignacionDirect
	case strings.Contains(n, "convocatoria_asamblea") ||
		strings.Contains(n, "convocatoria-asamblea"):
		return KindConvocatoriaAsamblea
	case strings.Contains(n, "acta_asamblea") ||
		strings.Contains(n, "acta-asamblea"):
		return KindActaAsamblea
	case strings.Contains(n, "contrato_fideicomiso") ||
		strings.Contains(n, "contrato-fideicomiso"):
		return KindContratoFideicomiso
	case strings.Contains(n, "reglamento_gestion") ||
		strings.Contains(n, "reglamento-gestion"):
		return KindReglamentoGestion
	case strings.Contains(n, "adenda_"):
		return KindAdenda
	}
	return KindOther
}

// TipoEmisionFromText classifies a tipo emisión label.
func TipoEmisionFromText(s string) TipoEmision {
	t := strings.ToLower(strings.TrimSpace(s))
	switch {
	case t == "":
		return TipoUnknown
	case strings.Contains(t, "obligacion") && strings.Contains(t, "negociable"):
		return TipoONCorporativa
	case t == "on" || strings.Contains(t, "on-corporativa"):
		return TipoONCorporativa
	case strings.Contains(t, "fci") || strings.Contains(t, "fondo comun"):
		return TipoFCI
	case strings.Contains(t, "fideicomiso"):
		return TipoFideicomiso
	case strings.Contains(t, "accion"):
		return TipoAcciones
	case strings.Contains(t, "pagare"):
		return TipoPagare
	case strings.Contains(t, "cedear"):
		return TipoCEDEAR
	}
	return TipoOther
}

// EmisorCuitPrefixes — only juridical CUIT prefixes are valid
// emisores.
func EmisorCuitPrefixes() []string {
	return []string{"30", "33", "34"}
}

// IsValidEmisorCuitPrefix reports prefix membership.
func IsValidEmisorCuitPrefix(p string) bool {
	for _, v := range EmisorCuitPrefixes() {
		if v == p {
			return true
		}
	}
	return false
}

// cuitRE matches 11-digit CUIT bounded by non-digit / edges.
var cuitRE = regexp.MustCompile(`(?:^|\D)(\d{2})-?(\d{8})-?(\d)(?:\D|$)`)

// EmisorCuitFingerprint extracts (prefix, suffix4) from text.
// Only juridical-emisor prefixes are accepted.
func EmisorCuitFingerprint(text string) (prefix, suffix4 string) {
	m := cuitRE.FindStringSubmatch(text)
	if m == nil {
		return "", ""
	}
	prefix = m[1]
	suffix4 = m[2][len(m[2])-3:] + m[3]
	if !IsValidEmisorCuitPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// AnyNaturalPersonCuit reports whether any natural-person
// CUIT appears in the text (for BO / directorio detection).
func AnyNaturalPersonCuit(text string) bool {
	matches := cuitRE.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		switch m[1] {
		case "20", "23", "24", "27":
			return true
		}
	}
	return false
}

// tickerRE matches a typical Argentine ticker (3-6 alphas).
var tickerRE = regexp.MustCompile(`(?i)(?:ticker|simbolo|simbol|s[íi]mbolo)[\s:#=\-]{0,5}([A-Z]{3,6})`)

// TickerFromText extracts an emisor ticker from text.
func TickerFromText(text string) string {
	m := tickerRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.ToUpper(m[1])
}

// docIDRE matches a CNV AIF folio (5-10 digits, often with N° prefix).
var docIDRE = regexp.MustCompile(`(?i)(?:folio|aif[_\-\s]?id|n[°º]\s?aif)[\s:#=\-]{0,5}(\d{5,10})`)

// DocumentoAIFIDFromText extracts the AIF folio ID.
func DocumentoAIFIDFromText(text string) string {
	m := docIDRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// AnnotateSecurity sets derived booleans. Time-sensitive
// flags use the injected clock.
func AnnotateSecurity(r *Row) {
	AnnotateSecurityWithClock(r, time.Now)
}

// AnnotateSecurityWithClock is the time-injectable variant.
func AnnotateSecurityWithClock(r *Row, now func() time.Time) {
	if r.FileMode != 0 {
		r.IsWorldReadable = r.FileMode&0o004 != 0
		r.IsGroupReadable = r.FileMode&0o040 != 0
	}
	if r.BeneficialOwnerCount > 0 {
		r.HasBeneficialOwner = true
	}
	// Active offering window: vigencia_desde <= now <= vigencia_hasta.
	if r.VigenciaDesde != "" && r.VigenciaHasta != "" {
		from, err1 := time.Parse("2006-01-02", r.VigenciaDesde)
		to, err2 := time.Parse("2006-01-02", r.VigenciaHasta)
		if err1 == nil && err2 == nil {
			n := now()
			if (n.Equal(from) || n.After(from)) && (n.Equal(to) || n.Before(to)) {
				r.IsActiveOffering = true
			}
		}
	}
	hasReadable := r.IsWorldReadable || r.IsGroupReadable
	hasPII := r.HasBeneficialOwner || r.HasDirectorioChange
	if hasReadable && r.EmisorCuitPrefix != "" && hasPII {
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
		return rs[i].FechaAprobacion < rs[j].FechaAprobacion
	})
}
