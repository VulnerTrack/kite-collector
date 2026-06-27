// Package wintango audits Argentine commercial ERP packages —
// Tango Gestión (Axoft), Bejerman, Astor — deployed on
// Windows accounting workstations. These ERPs persist all
// per-empresa books as proprietary Tango DBase tables on disk
// under a stable structure:
//
//	<install>\Empresas\<EMPRESA-NAME>\
//	  Sueldos\        (HR / payroll PII)
//	  Ventas\         (sales)
//	  Compras\        (purchases)
//	  Contabilidad\   (general ledger)
//	  Stock\          (inventory)
//	  Tesoreria\      (treasury / banking)
//	  Activos\        (fixed assets)
//	  *.tdb *.fpt *.cdx *.idx
//
// Multi-empresa hosts are the norm for estudios contables and
// corporate groups — the multi-tenancy itself is the
// discovery signal.
//
// Headline finding shapes:
//
//   - `has_sueldos_module=1` — Sueldos subdir present. The
//     empresa runs payroll through the ERP; the directory
//     contains HR PII under Ley 25.326.
//   - `has_multiple_empresas=1` — install carries >1 empresa.
//     Service-bureau host.
//   - `is_recently_modified=1` — at least one Tango data file
//     touched in the last 90 days.
//   - `is_credential_exposure_risk=1` — empresa dir readable
//     AND carries Sueldos or Tesoreria module.
//
// Read-only by intent — we list directories and stat files;
// we do NOT open the proprietary tables. (Project guideline 4.2.)
package wintango

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxRows bounds per-scan output.
const MaxRows = 4096

// RecentlyModifiedWindow defines the cutoff for
// is_recently_modified.
const RecentlyModifiedWindow = 90 * 24 * time.Hour

// Vendor pinned to host_tango_empresas.vendor enum.
type Vendor string

const (
	VendorTango    Vendor = "tango"
	VendorBejerman Vendor = "bejerman"
	VendorAxoft    Vendor = "axoft"
	VendorAstor    Vendor = "astor"
	VendorOther    Vendor = "other"
	VendorUnknown  Vendor = "unknown"
)

// Row mirrors host_tango_empresas' column shape exactly.
type Row struct {
	InstallRoot              string `json:"install_root"`
	EmpresaDir               string `json:"empresa_dir"`
	EmpresaName              string `json:"empresa_name,omitempty"`
	Denominacion             string `json:"denominacion,omitempty"`
	Vendor                   Vendor `json:"vendor"`
	CuitEntityPrefix         string `json:"cuit_entity_prefix,omitempty"`
	CuitSuffix4              string `json:"cuit_suffix4,omitempty"`
	LastModified             string `json:"last_modified,omitempty"`
	DirMode                  int    `json:"dir_mode,omitempty"`
	DirOwnerUID              int    `json:"dir_owner_uid,omitempty"`
	DataFilesCount           int    `json:"data_files_count,omitempty"`
	ModuleCount              int    `json:"module_count,omitempty"`
	HasSueldosModule         bool   `json:"has_sueldos_module"`
	HasVentasModule          bool   `json:"has_ventas_module"`
	HasComprasModule         bool   `json:"has_compras_module"`
	HasContabilidadModule    bool   `json:"has_contabilidad_module"`
	HasStockModule           bool   `json:"has_stock_module"`
	HasTesoreriaModule       bool   `json:"has_tesoreria_module"`
	HasActivosModule         bool   `json:"has_activos_module"`
	HasMultipleEmpresas      bool   `json:"has_multiple_empresas"`
	IsRecentlyModified       bool   `json:"is_recently_modified"`
	IsWorldReadable          bool   `json:"is_world_readable"`
	IsGroupReadable          bool   `json:"is_group_readable"`
	IsCredentialExposureRisk bool   `json:"is_credential_exposure_risk"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Row, error)
}

// InstallRoot describes a curated vendor install path.
type InstallRoot struct {
	Path   string
	Vendor Vendor
}

// DefaultInstallRoots is the curated set of ERP install roots
// across Windows locales + common non-Windows mounts.
func DefaultInstallRoots() []InstallRoot {
	return []InstallRoot{
		{`C:\Tango`, VendorTango},
		{`C:\Axoft`, VendorAxoft},
		{`C:\Axoft\Tango`, VendorTango},
		{`C:\Program Files\Axoft\Tango`, VendorTango},
		{`C:\Program Files (x86)\Axoft\Tango`, VendorTango},
		{`C:\Bejerman`, VendorBejerman},
		{`C:\Astor`, VendorAstor},
		// Non-Windows test mounts:
		{"/opt/tango", VendorTango},
		{"/srv/tango", VendorTango},
	}
}

// EmpresasDirNames is the curated set of subdir names ERPs
// use for their per-empresa data catalogue.
func EmpresasDirNames() []string {
	return []string{"Empresas", "empresas", "EMPRESAS", "Companies", "Bases"}
}

// ModuleDirs is the curated set of canonical module subdir
// names ERPs install per empresa. Matched case-insensitively.
func ModuleDirs() []string {
	return []string{
		"Sueldos", "Ventas", "Compras", "Contabilidad",
		"Stock", "Tesoreria", "Activos",
	}
}

// VendorFromRoot reports the vendor associated with the
// install root.
func VendorFromRoot(roots []InstallRoot, root string) Vendor {
	for _, r := range roots {
		if strings.EqualFold(r.Path, root) {
			return r.Vendor
		}
	}
	return VendorUnknown
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

// CuitFingerprint extracts prefix + suffix4 from a CUIT string.
func CuitFingerprint(raw string) (prefix, suffix4 string) {
	t := strings.TrimSpace(raw)
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

// IsDataFileExt reports whether `ext` is a Tango-DBase data
// extension.
func IsDataFileExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".tdb", ".fpt", ".cdx", ".idx", ".dbf", ".dat", ".mem":
		return true
	}
	return false
}

// MaxDenominationChars bounds persisted denomination length.
const MaxDenominationChars = 128

// TruncateDenominacion shortens a denomination preserving
// UTF-8 boundaries.
func TruncateDenominacion(s string) string {
	t := strings.TrimSpace(s)
	if len(t) <= MaxDenominationChars {
		return t
	}
	r := []rune(t)
	if len(r) <= MaxDenominationChars {
		return t
	}
	return string(r[:MaxDenominationChars])
}

// SetModuleFlag toggles the per-module boolean on a Row based
// on the lowercase module-subdir name.
func SetModuleFlag(r *Row, moduleName string) {
	switch strings.ToLower(moduleName) {
	case "sueldos":
		r.HasSueldosModule = true
	case "ventas":
		r.HasVentasModule = true
	case "compras":
		r.HasComprasModule = true
	case "contabilidad":
		r.HasContabilidadModule = true
	case "stock":
		r.HasStockModule = true
	case "tesoreria":
		r.HasTesoreriaModule = true
	case "activos":
		r.HasActivosModule = true
	}
}

// AnnotateSecurity sets the derived booleans. Caller populates
// DirMode + module flags first.
func AnnotateSecurity(r *Row) {
	if r.DirMode != 0 {
		r.IsWorldReadable = r.DirMode&0o004 != 0
		r.IsGroupReadable = r.DirMode&0o040 != 0
	}
	// PII / sensitive modules: Sueldos (HR PII) and Tesoreria
	// (banking data).
	sensitive := r.HasSueldosModule || r.HasTesoreriaModule
	if sensitive && (r.IsWorldReadable || r.IsGroupReadable) {
		r.IsCredentialExposureRisk = true
	}
}

// SortRows returns a deterministic ordering by install_root,
// vendor, empresa_dir.
func SortRows(rs []Row) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].InstallRoot != rs[j].InstallRoot {
			return rs[i].InstallRoot < rs[j].InstallRoot
		}
		if rs[i].Vendor != rs[j].Vendor {
			return rs[i].Vendor < rs[j].Vendor
		}
		return rs[i].EmpresaDir < rs[j].EmpresaDir
	})
}

// JoinEmpresasPath builds the canonical <root>/Empresas path.
func JoinEmpresasPath(root string) string {
	return filepath.Join(root, "Empresas")
}
