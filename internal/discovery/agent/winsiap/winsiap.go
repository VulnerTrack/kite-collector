// Package winsiap audits Argentine S.I.Ap (Sistema Integrado
// de Aplicaciones AFIP) deployments on Windows accounting
// workstations. SIAP is the legacy 32-bit Foxpro VFP9
// application stack every contador uses to file the formal
// AFIP forms that aren't covered by the modern web-only "Mis
// Aplicaciones" portal: F.931 (sueldos / cargas sociales),
// Ganancias Personas Físicas, Bienes Personales, Mis Aportes,
// Convenio Multilateral CM05, F.184 (autónomos), etc.
//
// Deployment shape is identical across every host:
//
//	C:\Archivos de programa\S.I.Ap\
//	  Aplicaciones\<APP-NAME>\
//	    <CUIT-SUBDIR>\
//	      *.dat  *.dbf  *.cdx  *.idx  *.fpt
//
// Each per-CUIT subdir holds local Foxpro tables for one
// legal entity. Workstations belonging to estudios contables
// carry dozens of CUIT subdirs — the multi-tenancy itself is
// the discovery signal.
//
// Headline finding shapes (Tax + PII context):
//
//   - `is_legacy_siap=1` — directory matches the SIAP shape.
//     EOL-class software; AFIP is actively migrating users off.
//   - `has_multiple_cuit_subdirs=1` — application directory
//     holds MORE than one CUIT subdir. Service-bureau host.
//   - `is_payroll_data=1` — application is F.931 or another
//     payroll-class app (Ley 25.326 HR PII).
//   - `is_recently_modified=1` — at least one data file
//     modified in the last 90 days. Active install vs.
//     abandoned residue.
//   - `is_credential_exposure_risk=1` — readable data dir +
//     payroll- or asset-declaration-class app.
//
// Read-only by intent — we list directories and stat files;
// we do NOT open the Foxpro tables. (Project guideline 4.2.)
package winsiap

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output. A heavy service-bureau host
// may carry ~10 apps × ~200 CUITs = 2000 rows; 8192 covers
// the long tail.
const MaxRows = 8192

// RecentlyModifiedWindow defines the cutoff for
// is_recently_modified.
const RecentlyModifiedWindow = 90 * 24 * time.Hour

// ApplicationCategory pinned to the
// host_siap_installations.application_category CHECK enum.
type ApplicationCategory string

const (
	CategoryPayroll          ApplicationCategory = "payroll"
	CategoryIncomeTax        ApplicationCategory = "income-tax"
	CategoryAutonomos        ApplicationCategory = "autonomos"
	CategoryConvMultilateral ApplicationCategory = "conv-multilateral"
	CategoryBienesPersonales ApplicationCategory = "bienes-personales"
	CategoryMisAportes       ApplicationCategory = "mis-aportes"
	CategoryIVA              ApplicationCategory = "iva"
	CategoryRetenciones      ApplicationCategory = "retenciones"
	CategoryOther            ApplicationCategory = "other"
	CategoryUnknown          ApplicationCategory = "unknown"
)

// Row mirrors host_siap_installations' column shape exactly.
type Row struct {
	CuitSuffix4              string              `json:"cuit_suffix4,omitempty"`
	ApplicationDir           string              `json:"application_dir"`
	CuitDir                  string              `json:"cuit_dir,omitempty"`
	LastModified             string              `json:"last_modified,omitempty"`
	InstallRoot              string              `json:"install_root"`
	ApplicationName          string              `json:"application_name,omitempty"`
	ApplicationCategory      ApplicationCategory `json:"application_category"`
	CuitEntityPrefix         string              `json:"cuit_entity_prefix,omitempty"`
	DatFilesCount            int                 `json:"dat_files_count,omitempty"`
	DataFilesCount           int                 `json:"data_files_count,omitempty"`
	DirOwnerUID              int                 `json:"dir_owner_uid,omitempty"`
	DbfFilesCount            int                 `json:"dbf_files_count,omitempty"`
	DirMode                  int                 `json:"dir_mode,omitempty"`
	IsLegacySIAP             bool                `json:"is_legacy_siap"`
	HasMultipleCuitSubdirs   bool                `json:"has_multiple_cuit_subdirs"`
	IsPayrollData            bool                `json:"is_payroll_data"`
	IsRecentlyModified       bool                `json:"is_recently_modified"`
	IsWorldReadable          bool                `json:"is_world_readable"`
	IsGroupReadable          bool                `json:"is_group_readable"`
	IsCredentialExposureRisk bool                `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// DefaultInstallRoots is the curated set of SIAP install roots
// across Windows locales.
func DefaultInstallRoots() []string {
	return []string{
		`C:\Archivos de programa\S.I.Ap`,
		`C:\Archivos de programa (x86)\S.I.Ap`,
		`C:\Program Files\S.I.Ap`,
		`C:\Program Files (x86)\S.I.Ap`,
		// Non-Windows test mounts:
		"/opt/SIAp",
		"/srv/SIAp",
	}
}

// AplicacionesDirNames is the curated set of subdir names
// SIAP uses for its app catalogue across locales.
func AplicacionesDirNames() []string {
	return []string{"Aplicaciones", "aplicaciones", "Applications", "applications"}
}

// CategoryFromAppName classifies the application directory
// name. The mapping is heuristic but covers the AFIP-published
// catalogue.
func CategoryFromAppName(name string) ApplicationCategory {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return CategoryUnknown
	case strings.Contains(n, "f931") || strings.Contains(n, "sicoss") || strings.Contains(n, "sueldo"):
		return CategoryPayroll
	case strings.Contains(n, "ganancias") || strings.Contains(n, "f572") || strings.Contains(n, "ganpf"):
		return CategoryIncomeTax
	case strings.Contains(n, "autonomo") || strings.Contains(n, "f184"):
		return CategoryAutonomos
	case strings.Contains(n, "cm05") || strings.Contains(n, "convenio-multilateral") || strings.Contains(n, "siframp"):
		return CategoryConvMultilateral
	case strings.Contains(n, "bienes") || strings.Contains(n, "bp-personas"):
		return CategoryBienesPersonales
	case strings.Contains(n, "mis-aportes") || strings.Contains(n, "mis_aportes") || strings.Contains(n, "misaportes"):
		return CategoryMisAportes
	case strings.Contains(n, "iva") || strings.Contains(n, "f2002"):
		return CategoryIVA
	case strings.Contains(n, "siref") || strings.Contains(n, "retencion"):
		return CategoryRetenciones
	}
	return CategoryOther
}

// PayrollCategories returns the set of categories that hold
// HR PII and should flip is_payroll_data.
func PayrollCategories() []ApplicationCategory {
	return []ApplicationCategory{
		CategoryPayroll,
		CategoryRetenciones,
	}
}

// IsPayrollCategory reports membership in PayrollCategories.
func IsPayrollCategory(c ApplicationCategory) bool {
	for _, v := range PayrollCategories() {
		if v == c {
			return true
		}
	}
	return false
}

// ExposureCategories returns the set of categories that, if
// readable, flip is_credential_exposure_risk. Includes payroll
// + asset declarations (Bienes Personales is unique PII).
func ExposureCategories() []ApplicationCategory {
	return []ApplicationCategory{
		CategoryPayroll,
		CategoryRetenciones,
		CategoryBienesPersonales,
		CategoryIncomeTax,
		CategoryMisAportes,
	}
}

// IsExposureCategory reports membership in ExposureCategories.
func IsExposureCategory(c ApplicationCategory) bool {
	for _, v := range ExposureCategories() {
		if v == c {
			return true
		}
	}
	return false
}

// CuitEntityPrefixes mirrors the AFIP collector list.
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

// CuitFingerprintFromSubdir extracts (prefix, suffix4) from a
// CUIT-shaped subdir name. Accepts `XX-XXXXXXXX-X`, `XX_..._X`,
// or bare 11-digit forms. Non-matching names return "","".
func CuitFingerprintFromSubdir(name string) (prefix, suffix4 string) {
	t := strings.TrimSpace(name)
	digits := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		if c := t[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) != 11 {
		return "", ""
	}
	prefix = string(digits[:2])
	suffix4 = string(digits[7:])
	if !IsValidCuitEntityPrefix(prefix) {
		return "", ""
	}
	return prefix, suffix4
}

// IsDataFileExt reports whether `ext` (with leading dot,
// case-insensitive) is a Foxpro data-table extension.
func IsDataFileExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".dat", ".dbf", ".cdx", ".idx", ".fpt", ".mem":
		return true
	}
	return false
}

// AnnotateSecurity sets the derived booleans. Caller populates
// DirMode + ApplicationCategory + counts beforehand.
func AnnotateSecurity(r *Row) {
	if r.DirMode != 0 {
		r.IsWorldReadable = r.DirMode&0o004 != 0
		r.IsGroupReadable = r.DirMode&0o040 != 0
	}
	r.IsPayrollData = IsPayrollCategory(r.ApplicationCategory)
	if r.IsPayrollData || IsExposureCategory(r.ApplicationCategory) {
		if r.IsWorldReadable || r.IsGroupReadable {
			r.IsCredentialExposureRisk = true
		}
	}
}

// SortRows returns a deterministic ordering by install_root,
// application_dir, then cuit_dir.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].InstallRoot != rs[j].InstallRoot {
			return rs[i].InstallRoot < rs[j].InstallRoot
		}
		if rs[i].ApplicationDir != rs[j].ApplicationDir {
			return rs[i].ApplicationDir < rs[j].ApplicationDir
		}
		return rs[i].CuitDir < rs[j].CuitDir
	})
}

// JoinAplicacionesPath builds the canonical
// <root>/Aplicaciones path.
func JoinAplicacionesPath(root string) string {
	return filepath.Join(root, "Aplicaciones")
}
