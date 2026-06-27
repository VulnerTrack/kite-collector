// Package winpsmodules inventories PowerShell module manifests
// from the standard PSModulePath directories on Windows. Each
// `.psd1` is a constrained PowerShell expression returning a
// hash-table of metadata — we extract the security-relevant scalar
// fields (ModuleVersion, Author, RootModule, …) using a minimal
// purpose-built scanner.
//
// File-based discovery is the deliberate design choice: every
// installed module ships a .psd1 manifest at a predictable path,
// and the audit pipeline can hash it for drift detection without
// invoking PowerShell. Manifests are tiny — even module farms with
// 1k+ entries inventory in under a second.
//
// Headline finding shapes (MITRE T1546 — Event Triggered Execution,
// T1059.001 — PowerShell, T1195 — Supply Chain Compromise):
//
//   - `is_user_scoped=1` — module under the per-user Documents
//     PowerShell\Modules path. Legitimate dev work happens here,
//     but persistence implants prefer the location because UAC is
//     not required to write it (CWE-732).
//   - `has_binary_root_module=1` — RootModule references a .dll;
//     binary modules need Authenticode signing to be trusted in
//     scale-out deployments.
//   - `is_missing_author=1` / `is_missing_company=1` — every
//     official Microsoft / community module ships both. Missing
//     values are common for hand-rolled / implant modules.
//   - `has_root_module_outside_dir=1` — RootModule path escapes the
//     manifest's directory (e.g. `..\..\foo.dll`). Suspicious by
//     definition; legitimate manifests reference siblings only.
//
// Read-only by intent — we walk the module-path directories only,
// never invoke PowerShell. (Project guideline 4.2.)
package winpsmodules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxModules bounds per-scan output. A loaded admin workstation has
// 200-800 modules; the 8192 ceiling covers heavily-customised
// SaaS-administrator boxes without bloating SQLite writes.
const MaxModules = 8192

// InstallScope tags where the module lives. Pinned to the
// host_powershell_modules.install_scope CHECK enum.
type InstallScope string

const (
	ScopeSystem  InstallScope = "system"
	ScopeUser    InstallScope = "user"
	ScopeUnknown InstallScope = "unknown"
)

// SystemModulePathRoots is the curated set of directory prefixes
// that count as a "system-wide" module install location. Anything
// not under one of these flags as user-scoped (or unknown).
func SystemModulePathRoots() []string {
	return []string{
		`c:\program files\powershell\modules`,
		`c:\program files\powershell\7\modules`,
		`c:\program files\powershell\6\modules`,
		`c:\program files\windowspowershell\modules`,
		`c:\program files (x86)\windowspowershell\modules`,
		`c:\windows\system32\windowspowershell\v1.0\modules`,
		`c:\windows\syswow64\windowspowershell\v1.0\modules`,
	}
}

// UserModulePathRoots is the curated set of per-user prefixes.
// Substrings used because the username segment varies.
func UserModulePathRoots() []string {
	return []string{
		`\documents\powershell\modules`,
		`\documents\windowspowershell\modules`,
		`\onedrive\documents\powershell\modules`, // Office 365 redirect
	}
}

// Module mirrors host_powershell_modules' column shape exactly.
type Module struct {
	FilePath                string       `json:"file_path"`
	FileHash                string       `json:"file_hash"`
	ModuleName              string       `json:"module_name"`
	ModuleVersion           string       `json:"module_version,omitempty"`
	GUID                    string       `json:"guid,omitempty"`
	Author                  string       `json:"author,omitempty"`
	CompanyName             string       `json:"company_name,omitempty"`
	Copyright               string       `json:"copyright,omitempty"`
	Description             string       `json:"description,omitempty"`
	PowerShellVersion       string       `json:"powershell_version,omitempty"`
	CLRVersion              string       `json:"clr_version,omitempty"`
	DotNetFrameworkVersion  string       `json:"dotnet_framework_version,omitempty"`
	RootModule              string       `json:"root_module,omitempty"`
	InstallScope            InstallScope `json:"install_scope"`
	IsUserScoped            bool         `json:"is_user_scoped"`
	HasBinaryRootModule     bool         `json:"has_binary_root_module"`
	IsMissingAuthor         bool         `json:"is_missing_author"`
	IsMissingCompany        bool         `json:"is_missing_company"`
	HasRootModuleOutsideDir bool         `json:"has_root_module_outside_dir"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Module, error)
}

// HashContents returns the SHA-256 hex of a manifest body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ClassifyInstallScope maps a manifest's on-disk path to an
// InstallScope. Case-insensitive match against the curated roots.
func ClassifyInstallScope(filePath string) InstallScope {
	p := strings.ToLower(filepath.ToSlash(filePath))
	for _, root := range SystemModulePathRoots() {
		r := strings.ToLower(filepath.ToSlash(root))
		if strings.Contains(p, r) {
			return ScopeSystem
		}
	}
	for _, sub := range UserModulePathRoots() {
		s := strings.ToLower(filepath.ToSlash(sub))
		if strings.Contains(p, s) {
			return ScopeUser
		}
	}
	return ScopeUnknown
}

// IsBinaryRootModule reports whether a RootModule value points to a
// binary (.dll) rather than a script (.psm1) — case-insensitive.
func IsBinaryRootModule(root string) bool {
	v := strings.ToLower(strings.TrimSpace(root))
	if v == "" {
		return false
	}
	return strings.HasSuffix(v, ".dll") || strings.HasSuffix(v, ".cdxml")
}

// IsRootModuleOutsideDir reports whether a RootModule path escapes
// the manifest's directory — anything starting with `\\`, `/`, a
// drive letter (e.g. `C:\`), or containing `..` flags. Legitimate
// manifests reference siblings only.
func IsRootModuleOutsideDir(root string) bool {
	v := strings.TrimSpace(root)
	if v == "" {
		return false
	}
	v = strings.Trim(v, `"'`)
	// Absolute paths.
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, `\`) {
		return true
	}
	if len(v) >= 2 && v[1] == ':' {
		return true
	}
	// Parent escape.
	if strings.Contains(v, "..") {
		return true
	}
	return false
}

// AnnotateSecurity sets the derived booleans on a Module that has
// its raw fields populated.
func AnnotateSecurity(m *Module) {
	m.InstallScope = ClassifyInstallScope(m.FilePath)
	m.IsUserScoped = m.InstallScope == ScopeUser
	m.HasBinaryRootModule = IsBinaryRootModule(m.RootModule)
	m.IsMissingAuthor = strings.TrimSpace(m.Author) == ""
	m.IsMissingCompany = strings.TrimSpace(m.CompanyName) == ""
	m.HasRootModuleOutsideDir = IsRootModuleOutsideDir(m.RootModule)
}

// SortModules returns a deterministic ordering by module name then
// version.
func SortModules(ms []Module) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].ModuleName != ms[j].ModuleName {
			return ms[i].ModuleName < ms[j].ModuleName
		}
		return ms[i].ModuleVersion < ms[j].ModuleVersion
	})
}
