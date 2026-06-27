// Package winbcracomunic audits BCRA (Banco Central de la
// República Argentina) "Comunicaciones" cached on banking /
// compliance / risk workstations across Windows, Linux, and
// macOS.
//
// BCRA publishes mandatory regulatory advisories as
// Comunicaciones with type prefix:
//
//   - A — Normativa (rules)
//   - B — Operativa Monetaria
//   - C — Información General
//   - P — Política
//
// Compliance teams cache these as PDF / HTML / XML for active
// regulatory tracking. BCRA Comunicaciones are PUBLIC
// documents (no PII concern). The audit value is
// **regulatory-compliance-posture discovery**: which
// advisories does this workstation actively track? Forex
// (MULC / COTI / comercio exterior) and AML (UIF compliance)
// matter most for cross-collector correlation.
//
// Headline finding shapes:
//
//   - `is_forex_regulation=1` — materia in {cambios,
//     comercio-exterior}. Pairs with iter 100 export-invoice
//     collector for capital-flow risk picture.
//   - `is_aml_regulation=1` — materia=prevencion-lavado. Pairs
//     with iter 99 UIF ROS collector.
//   - `is_recent=1` — file modified within 90 days.
//   - `is_credential_exposure_risk=1` — INFORMATIONAL for
//     these public docs (kept for cross-collector parity).
//
// Read-only by intent. (Project guideline 4.2.)
package winbcracomunic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 16384

// MaxFileBytes bounds per-file read.
const MaxFileBytes = 4 << 20 // 4 MiB

// RecentlyWindow defines is_recent cutoff.
const RecentlyWindow = 90 * 24 * time.Hour

// MaxAsuntoChars bounds persisted asunto length.
const MaxAsuntoChars = 200

// ComunicacionKind pinned to comunicacion_kind enum.
type ComunicacionKind string

const (
	KindA       ComunicacionKind = "tipo-a"
	KindB       ComunicacionKind = "tipo-b"
	KindC       ComunicacionKind = "tipo-c"
	KindP       ComunicacionKind = "tipo-p"
	KindOther   ComunicacionKind = "other"
	KindUnknown ComunicacionKind = "unknown"
)

// Materia pinned to materia enum.
type Materia string

const (
	MateriaCambios          Materia = "cambios"
	MateriaDepositos        Materia = "depositos"
	MateriaCreditos         Materia = "creditos"
	MateriaNormativaGeneral Materia = "normativa-general"
	MateriaMonetaria        Materia = "monetaria"
	MateriaPrevencionLavado Materia = "prevencion-lavado"
	MateriaComercioExterior Materia = "comercio-exterior"
	MateriaEncajes          Materia = "encajes"
	MateriaTasas            Materia = "tasas"
	MateriaCapitalMinimo    Materia = "capital-minimo"
	MateriaSeguros          Materia = "seguros"
	MateriaCooperativas     Materia = "cooperativas"
	MateriaOther            Materia = "other"
	MateriaUnknown          Materia = "unknown"
)

// Row mirrors host_bcra_comunicaciones' column shape.
type Row struct {
	FechaEmision             string           `json:"fecha_emision,omitempty"`
	FechaVigencia            string           `json:"fecha_vigencia,omitempty"`
	Asunto                   string           `json:"asunto,omitempty"`
	ModificaA                string           `json:"modifica_a,omitempty"`
	FilePath                 string           `json:"file_path"`
	UserProfile              string           `json:"user_profile,omitempty"`
	ComunicacionKind         ComunicacionKind `json:"comunicacion_kind"`
	Numero                   string           `json:"numero,omitempty"`
	SustituyeA               string           `json:"sustituye_a,omitempty"`
	Materia                  Materia          `json:"materia"`
	FileHash                 string           `json:"file_hash"`
	NumeroSerie              int              `json:"numero_serie,omitempty"`
	FileOwnerUID             int              `json:"file_owner_uid,omitempty"`
	FileMode                 int              `json:"file_mode,omitempty"`
	FileSize                 int64            `json:"file_size,omitempty"`
	IsForexRegulation        bool             `json:"is_forex_regulation"`
	IsAmlRegulation          bool             `json:"is_aml_regulation"`
	IsRecent                 bool             `json:"is_recent"`
	IsWorldReadable          bool             `json:"is_world_readable"`
	IsGroupReadable          bool             `json:"is_group_readable"`
	IsCredentialExposureRisk bool             `json:"is_credential_exposure_risk"`
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

// DefaultInstallRoots is the curated BCRA cache-root set.
func DefaultInstallRoots() []string {
	return []string{
		`C:\BCRA`,
		`C:\BCRA\Comunicaciones`,
		`C:\BCRA\Normativa`,
		`/opt/bcra`,
		`/opt/bcra/comunicaciones`,
		`/srv/bcra`,
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

// UserComDirs is the curated per-user relative path set.
func UserComDirs() [][]string {
	return [][]string{
		{"Documents", "BCRA"},
		{"Documents", "BCRA", "Comunicaciones"},
		{"Documents", "Compliance", "BCRA"},
		{"Documents", "Normativa", "BCRA"},
		{"Downloads"},
		{"Descargas"},
	}
}

// IsCandidateName reports whether a filename plausibly belongs
// to the BCRA Comunicaciones catalogue.
func IsCandidateName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(filepath.Base(name))
	for _, tok := range []string{
		"coma", "comb", "comc", "comp",
		"comunicacion_a", "comunicacion-a",
		"comunicacion_b", "comunicacion-b",
		"comunicacion_c", "comunicacion-c",
		"comunicacion_p", "comunicacion-p",
		"bcra_a", "bcra-a", "bcra_b", "bcra-b",
		"normativa_bcra", "boletin_bcra",
	} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// numeroRE matches `<letter><serie>` patterns with hyphen /
// underscore / space tolerance.
//
// Examples it must extract:
//   - Coma8137.pdf         → A 8137
//   - bcra_a_8137.xml      → A 8137
//   - comunicacion-a-8137  → A 8137
//   - BCRA_B-12345.pdf     → B 12345
var numeroRE = regexp.MustCompile(`(?i)(?:bcra[_-]?|com|comunicacion[_-]?)([abcp])[_\s-]*(\d{2,6})`)

// ParseNumero extracts (kind, numero_serie) from a filename or
// title string.
func ParseNumero(text string) (ComunicacionKind, int) {
	m := numeroRE.FindStringSubmatch(text)
	if m == nil {
		return KindUnknown, 0
	}
	letter := strings.ToUpper(m[1])
	serie, err := strconv.Atoi(m[2])
	if err != nil {
		return KindUnknown, 0
	}
	var kind ComunicacionKind
	switch letter {
	case "A":
		kind = KindA
	case "B":
		kind = KindB
	case "C":
		kind = KindC
	case "P":
		kind = KindP
	default:
		kind = KindOther
	}
	return kind, serie
}

// FormatNumero canonicalises a (kind, serie) into "A 8137".
func FormatNumero(kind ComunicacionKind, serie int) string {
	if serie == 0 {
		return ""
	}
	var letter string
	switch kind {
	case KindA:
		letter = "A"
	case KindB:
		letter = "B"
	case KindC:
		letter = "C"
	case KindP:
		letter = "P"
	case KindOther, KindUnknown:
		return ""
	default:
		return ""
	}
	return letter + " " + strconv.Itoa(serie)
}

// MateriaFromText classifies a textual subject / asunto body.
// Matched case-insensitively.
func MateriaFromText(s string) Materia {
	t := strings.ToLower(s)
	switch {
	case t == "":
		return MateriaUnknown
	case strings.Contains(t, "prevenc") && strings.Contains(t, "lavado"):
		return MateriaPrevencionLavado
	case strings.Contains(t, "prevenc") && strings.Contains(t, "financiamiento"):
		return MateriaPrevencionLavado
	case strings.Contains(t, "uif"):
		return MateriaPrevencionLavado
	case strings.Contains(t, "comercio exterior") || strings.Contains(t, "comercio-exterior") ||
		strings.Contains(t, "import") || strings.Contains(t, "export"):
		return MateriaComercioExterior
	case strings.Contains(t, "cambio") || strings.Contains(t, "mulc") ||
		strings.Contains(t, "divisas") || strings.Contains(t, "forex"):
		return MateriaCambios
	case strings.Contains(t, "encaje"):
		return MateriaEncajes
	case strings.Contains(t, "capital m") || strings.Contains(t, "capital_minimo"):
		return MateriaCapitalMinimo
	case strings.Contains(t, "depos") || strings.Contains(t, "plazo fijo"):
		return MateriaDepositos
	case strings.Contains(t, "credit") || strings.Contains(t, "créd") ||
		strings.Contains(t, "prestam"):
		return MateriaCreditos
	case strings.Contains(t, "tasa") || strings.Contains(t, "interes"):
		return MateriaTasas
	case strings.Contains(t, "monetar"):
		return MateriaMonetaria
	case strings.Contains(t, "seguro") || strings.Contains(t, "aseguradora"):
		return MateriaSeguros
	case strings.Contains(t, "cooperativ"):
		return MateriaCooperativas
	}
	return MateriaOther
}

// IsForexMateria reports whether the materia represents forex /
// trade-exterior regulation.
func IsForexMateria(m Materia) bool {
	switch m {
	case MateriaCambios, MateriaComercioExterior:
		return true
	case MateriaDepositos, MateriaCreditos, MateriaNormativaGeneral,
		MateriaMonetaria, MateriaPrevencionLavado, MateriaEncajes,
		MateriaTasas, MateriaCapitalMinimo, MateriaSeguros,
		MateriaCooperativas, MateriaOther, MateriaUnknown:
		return false
	}
	return false
}

// IsAmlMateria reports whether the materia is AML.
func IsAmlMateria(m Materia) bool {
	return m == MateriaPrevencionLavado
}

// MaxStringLen truncates a string preserving UTF-8.
func MaxStringLen(s string, max int) string {
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
	r.IsForexRegulation = IsForexMateria(r.Materia)
	r.IsAmlRegulation = IsAmlMateria(r.Materia)
	// Public docs — exposure_risk stays low. We only flag it
	// when the workstation has cached a non-public draft (e.g.
	// internal compliance memo following the BCRA com.). Out of
	// scope for this collector.
	_ = r.IsCredentialExposureRisk
}

// SortRows returns deterministic ordering.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		if rs[i].ComunicacionKind != rs[j].ComunicacionKind {
			return rs[i].ComunicacionKind < rs[j].ComunicacionKind
		}
		return rs[i].NumeroSerie < rs[j].NumeroSerie
	})
}
