// Package windowsiis inventories Windows IIS websites + application
// pools via a PowerShell shim. Eleventh table-set of the MID Server-
// aligned Windows track.
//
// Returns an Inventory bundle (Sites + AppPools) so the store layer
// fans out into two table writes via asset_id from one PowerShell
// round-trip.
//
// MITRE T1190 (Exploit Public-Facing Application — defender side):
// the audit pipeline joins this against host_certificates (binding
// cert thumbprints), host_listeners (HTTP/HTTPS ports), and
// host_users (identity_username for SpecificUser pools).
package windowsiis

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Source identifies which probe produced the rows. Pinned to the
// host_windows_iis_sites.source / host_windows_iis_app_pools.source
// CHECK enums (same enum set).
type Source string

const (
	SourcePowerShellIISAdmin Source = "powershell-iisadmin"
	SourcePowerShellWebAdmin Source = "powershell-webadmin"
	SourceUnknown            Source = "unknown"
)

// Binding is one IIS binding record. Nested inside Site.bindings_json
// — the audit pipeline fans it out at query time when joining against
// the cert store.
type Binding struct {
	Protocol           string `json:"protocol"`
	BindingInformation string `json:"binding_information"`
	IPAddress          string `json:"ip_address,omitempty"`
	Hostname           string `json:"hostname,omitempty"`
	CertHash           string `json:"certificate_hash,omitempty"`
	CertStoreName      string `json:"certificate_store_name,omitempty"`
	Port               int    `json:"port,omitempty"`
}

// Site mirrors host_windows_iis_sites' column shape.
type Site struct {
	Source           Source    `json:"source"`
	SiteName         string    `json:"site_name"`
	State            string    `json:"state,omitempty"`
	PhysicalPath     string    `json:"physical_path,omitempty"`
	AppPoolName      string    `json:"app_pool_name,omitempty"`
	EnabledProtocols string    `json:"enabled_protocols,omitempty"`
	LogDirectory     string    `json:"log_directory,omitempty"`
	Bindings         []Binding `json:"bindings,omitempty"`
	SiteID           int       `json:"site_id"`
	IsRunning        bool      `json:"is_running"`
	HasHTTPBinding   bool      `json:"has_http_binding"`
	HasHTTPSBinding  bool      `json:"has_https_binding"`
}

// AppPool mirrors host_windows_iis_app_pools' column shape.
type AppPool struct {
	IdentityUsername      string `json:"identity_username,omitempty"`
	PoolName              string `json:"pool_name"`
	State                 string `json:"state,omitempty"`
	ManagedRuntimeVersion string `json:"managed_runtime_version,omitempty"`
	ManagedPipelineMode   string `json:"managed_pipeline_mode,omitempty"`
	IdentityType          string `json:"identity_type,omitempty"`
	Source                Source `json:"source"`
	StartMode             string `json:"start_mode,omitempty"`
	IdleTimeoutMinutes    int    `json:"idle_timeout_minutes,omitempty"`
	Enable32BitOn64Bit    bool   `json:"enable_32bit_on_64bit"`
	AutoStart             bool   `json:"auto_start"`
	IsRunning             bool   `json:"is_running"`
	IsPrivilegedIdentity  bool   `json:"is_privileged_identity"`
}

// Inventory bundles both entity slices.
type Inventory struct {
	Sites    []Site    `json:"sites"`
	AppPools []AppPool `json:"app_pools"`
}

// Collector is the read-only contract every per-OS implementation
// satisfies. Windows: PowerShell shim. Other OSes: empty Inventory.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (Inventory, error)
}

// EncodeBindings serialises a Binding slice into the JSON array
// suitable for the bindings_json column. Empty input always emits
// "[]" so the column is never NULL.
func EncodeBindings(bs []Binding) string {
	if len(bs) == 0 {
		return "[]"
	}
	b, err := json.Marshal(bs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// PrivilegedIdentityTypes is the curated set of IIS app-pool identity
// types that grant elevated privileges. Drawn from the IIS
// documentation — LocalSystem is the worst, the others are scoped.
func PrivilegedIdentityTypes() []string {
	return []string{"LocalSystem"}
}

// IsPrivilegedIdentity reports whether a pool's identity_type grants
// root-equivalent privileges. Used by the CWE-250 audit rule.
func IsPrivilegedIdentity(identityType string) bool {
	want := strings.TrimSpace(identityType)
	for _, t := range PrivilegedIdentityTypes() {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// IsHTTPProtocol reports whether a binding protocol is plain HTTP.
// Used to flag the CWE-319 case.
func IsHTTPProtocol(proto string) bool {
	return strings.EqualFold(strings.TrimSpace(proto), "http")
}

// IsHTTPSProtocol reports whether a binding protocol is HTTPS.
func IsHTTPSProtocol(proto string) bool {
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// AnnotateSite derives the HasHTTP/HTTPS booleans from the bindings
// list. Centralised so the parser and any future enrichment paths
// share the same classification.
func AnnotateSite(s *Site) {
	s.HasHTTPBinding = false
	s.HasHTTPSBinding = false
	for _, b := range s.Bindings {
		if IsHTTPProtocol(b.Protocol) {
			s.HasHTTPBinding = true
		}
		if IsHTTPSProtocol(b.Protocol) {
			s.HasHTTPSBinding = true
		}
	}
	s.IsRunning = strings.EqualFold(strings.TrimSpace(s.State), "Started")
}

// AnnotateAppPool derives the privileged-identity + running flags.
func AnnotateAppPool(p *AppPool) {
	p.IsPrivilegedIdentity = IsPrivilegedIdentity(p.IdentityType)
	p.IsRunning = strings.EqualFold(strings.TrimSpace(p.State), "Started")
}

// SortSites returns a deterministic ordering: site_name.
func SortSites(ss []Site) {
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].SiteName < ss[j].SiteName
	})
}

// SortAppPools returns a deterministic ordering: pool_name.
func SortAppPools(ps []AppPool) {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].PoolName < ps[j].PoolName
	})
}

// SortInventory normalises both slices in place.
func SortInventory(inv *Inventory) {
	if inv == nil {
		return
	}
	SortSites(inv.Sites)
	SortAppPools(inv.AppPools)
}
