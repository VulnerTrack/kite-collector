package windowsiis

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PowerShellScript captures all IIS sites + app pools in one
// round-trip. It tries `IISAdministration` first (Get-IISSite /
// Get-IISAppPool), falling back to the older `WebAdministration`
// module (Get-Website / Get-IISAppPool absent). Either module is
// shipped with the IIS feature on Windows Server / Workstation
// (with IIS Management Tools installed).
//
// For each binding we parse the bindingInformation tuple
// "<ip>:<port>:<hostname>" on the PowerShell side so the Go decoder
// receives structured fields without re-tokenising.
const PowerShellScript = `
$ErrorActionPreference = 'Stop'
Import-Module IISAdministration -ErrorAction SilentlyContinue
Import-Module WebAdministration -ErrorAction SilentlyContinue

$source = 'powershell-iisadmin'
$sites = @()
try {
    $sites = @(Get-IISSite -ErrorAction Stop)
} catch {
    try {
        $sites = @(Get-Website -ErrorAction Stop)
        $source = 'powershell-webadmin'
    } catch {}
}

$pools = @()
try {
    $pools = @(Get-IISAppPool -ErrorAction Stop)
} catch {
    try {
        $pools = @(Get-Item 'IIS:\AppPools\*' -ErrorAction SilentlyContinue)
    } catch {}
}

function ParseBindingInfo([string]$bindingInfo) {
    # Format: <ip>:<port>:<hostname>
    if ([string]::IsNullOrEmpty($bindingInfo)) {
        return [pscustomobject]@{ ip_address = ''; port = 0; hostname = '' }
    }
    $parts = $bindingInfo.Split(':', 3)
    $ip = if ($parts.Count -gt 0) { [string]$parts[0] } else { '' }
    $port = 0
    if ($parts.Count -gt 1 -and [int]::TryParse($parts[1], [ref]$port)) {} else { $port = 0 }
    $host = if ($parts.Count -gt 2) { [string]$parts[2] } else { '' }
    return [pscustomobject]@{
        ip_address = $ip
        port       = $port
        hostname   = $host
    }
}

$siteRows = @($sites | ForEach-Object {
    $rootApp = $null
    if ($_.Applications) { $rootApp = $_.Applications | Where-Object { $_.Path -eq '/' } | Select-Object -First 1 }
    $rootVdir = $null
    if ($rootApp -and $rootApp.VirtualDirectories) { $rootVdir = $rootApp.VirtualDirectories | Where-Object { $_.Path -eq '/' } | Select-Object -First 1 }
    $physicalPath = if ($rootVdir) { [string]$rootVdir.PhysicalPath } else { '' }
    $appPool = if ($rootApp) { [string]$rootApp.ApplicationPoolName } else { '' }

    $bindings = @()
    if ($_.Bindings -and $_.Bindings.Collection) {
        $bindings = @($_.Bindings.Collection | ForEach-Object {
            $parsed = ParseBindingInfo([string]$_.bindingInformation)
            [pscustomobject]@{
                protocol               = [string]$_.protocol
                binding_information    = [string]$_.bindingInformation
                ip_address             = $parsed.ip_address
                port                   = $parsed.port
                hostname               = $parsed.hostname
                certificate_hash       = if ($_.certificateHash) { [string]$_.certificateHash } else { '' }
                certificate_store_name = if ($_.certificateStoreName) { [string]$_.certificateStoreName } else { '' }
            }
        })
    } elseif ($_.Bindings) {
        # WebAdministration shape: Bindings is a string array "http *:80:" etc.
        $bindings = @($_.Bindings | ForEach-Object {
            $token = [string]$_
            $protocol = $token.Split(' ', 2)[0]
            $info = if ($token.Contains(' ')) { $token.Substring($token.IndexOf(' ') + 1) } else { '' }
            $parsed = ParseBindingInfo($info)
            [pscustomobject]@{
                protocol               = $protocol
                binding_information    = $info
                ip_address             = $parsed.ip_address
                port                   = $parsed.port
                hostname               = $parsed.hostname
                certificate_hash       = ''
                certificate_store_name = ''
            }
        })
    }

    [pscustomobject]@{
        site_id           = if ($_.Id -ne $null) { [int]$_.Id } else { 0 }
        site_name         = [string]$_.Name
        state             = [string]$_.State
        physical_path     = $physicalPath
        app_pool_name     = $appPool
        enabled_protocols = if ($rootApp) { [string]$rootApp.EnabledProtocols } else { '' }
        bindings          = $bindings
        log_directory     = if ($_.LogFile) { [string]$_.LogFile.Directory } else { '' }
    }
})

$poolRows = @($pools | ForEach-Object {
    $id = $null
    if ($_.PSObject.Properties['Attributes'] -and $_.Attributes['identityType']) {
        # Get-Item shape
        $id = $_.Attributes['identityType'].Value
    }
    $identType = if ($_.ProcessModel -and $_.ProcessModel.IdentityType -ne $null) {
        [string]$_.ProcessModel.IdentityType
    } elseif ($id) {
        [string]$id
    } else { '' }
    $identUser = if ($_.ProcessModel -and $_.ProcessModel.UserName) {
        [string]$_.ProcessModel.UserName
    } else { '' }
    $idleMin = 0
    if ($_.ProcessModel -and $_.ProcessModel.IdleTimeout) {
        try { $idleMin = [int]([timespan]$_.ProcessModel.IdleTimeout).TotalMinutes } catch {}
    }

    [pscustomobject]@{
        pool_name                = [string]$_.Name
        state                    = [string]$_.State
        managed_runtime_version  = [string]$_.ManagedRuntimeVersion
        managed_pipeline_mode    = [string]$_.ManagedPipelineMode
        identity_type            = $identType
        identity_username        = $identUser
        enable_32bit_on_64bit    = [bool]$_.Enable32BitAppOnWin64
        idle_timeout_minutes     = $idleMin
        start_mode               = [string]$_.StartMode
        auto_start               = [bool]$_.AutoStart
    }
})

[pscustomobject]@{
    source    = [string]$source
    sites     = @($siteRows)
    app_pools = @($poolRows)
} | ConvertTo-Json -Depth 6 -Compress
`

// rawPayload mirrors the wire JSON shape.
type rawPayload struct {
	Source   string       `json:"source"`
	Sites    []rawSite    `json:"sites"`
	AppPools []rawAppPool `json:"app_pools"`
}

type rawBinding struct {
	Protocol           string      `json:"protocol"`
	BindingInformation string      `json:"binding_information"`
	IPAddress          string      `json:"ip_address"`
	Port               json.Number `json:"port"`
	Hostname           string      `json:"hostname"`
	CertHash           string      `json:"certificate_hash"`
	CertStoreName      string      `json:"certificate_store_name"`
}

type rawSite struct {
	SiteID           json.Number  `json:"site_id"`
	SiteName         string       `json:"site_name"`
	State            string       `json:"state"`
	PhysicalPath     string       `json:"physical_path"`
	AppPoolName      string       `json:"app_pool_name"`
	EnabledProtocols string       `json:"enabled_protocols"`
	LogDirectory     string       `json:"log_directory"`
	Bindings         []rawBinding `json:"bindings"`
}

type rawAppPool struct {
	PoolName              string      `json:"pool_name"`
	State                 string      `json:"state"`
	ManagedRuntimeVersion string      `json:"managed_runtime_version"`
	ManagedPipelineMode   string      `json:"managed_pipeline_mode"`
	IdentityType          string      `json:"identity_type"`
	IdentityUsername      string      `json:"identity_username"`
	IdleTimeoutMinutes    json.Number `json:"idle_timeout_minutes"`
	StartMode             string      `json:"start_mode"`
	Enable32BitOn64Bit    bool        `json:"enable_32bit_on_64bit"`
	AutoStart             bool        `json:"auto_start"`
}

// ParsePowerShellOutput converts the JSON payload into an Inventory.
// Singleton-object unwrap mirrors the rest of the windows* track.
func ParsePowerShellOutput(data []byte) (Inventory, error) {
	trimmed := trimUTF8BOM(data)
	trimmed = []byte(strings.TrimSpace(string(trimmed)))
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty PowerShell output")
	}
	normalised := unwrapSingletonArrays(trimmed)
	var raw rawPayload
	dec := json.NewDecoder(strings.NewReader(string(normalised)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode windows-iis json: %w", err)
	}
	source := normaliseSource(raw.Source)
	inv := Inventory{
		Sites:    make([]Site, 0, len(raw.Sites)),
		AppPools: make([]AppPool, 0, len(raw.AppPools)),
	}
	for _, r := range raw.Sites {
		name := strings.TrimSpace(r.SiteName)
		if name == "" {
			continue
		}
		s := Site{
			Source:           source,
			SiteID:           atoi(r.SiteID),
			SiteName:         name,
			State:            strings.TrimSpace(r.State),
			PhysicalPath:     strings.TrimSpace(r.PhysicalPath),
			AppPoolName:      strings.TrimSpace(r.AppPoolName),
			EnabledProtocols: strings.TrimSpace(r.EnabledProtocols),
			LogDirectory:     strings.TrimSpace(r.LogDirectory),
			Bindings:         make([]Binding, 0, len(r.Bindings)),
		}
		for _, b := range r.Bindings {
			s.Bindings = append(s.Bindings, Binding{
				Protocol:           strings.TrimSpace(b.Protocol),
				BindingInformation: strings.TrimSpace(b.BindingInformation),
				IPAddress:          strings.TrimSpace(b.IPAddress),
				Port:               atoi(b.Port),
				Hostname:           strings.TrimSpace(b.Hostname),
				CertHash:           strings.TrimSpace(b.CertHash),
				CertStoreName:      strings.TrimSpace(b.CertStoreName),
			})
		}
		AnnotateSite(&s)
		inv.Sites = append(inv.Sites, s)
	}
	for _, r := range raw.AppPools {
		name := strings.TrimSpace(r.PoolName)
		if name == "" {
			continue
		}
		p := AppPool{
			Source:                source,
			PoolName:              name,
			State:                 strings.TrimSpace(r.State),
			ManagedRuntimeVersion: strings.TrimSpace(r.ManagedRuntimeVersion),
			ManagedPipelineMode:   strings.TrimSpace(r.ManagedPipelineMode),
			IdentityType:          strings.TrimSpace(r.IdentityType),
			IdentityUsername:      strings.TrimSpace(r.IdentityUsername),
			Enable32BitOn64Bit:    r.Enable32BitOn64Bit,
			IdleTimeoutMinutes:    atoi(r.IdleTimeoutMinutes),
			StartMode:             strings.TrimSpace(r.StartMode),
			AutoStart:             r.AutoStart,
		}
		AnnotateAppPool(&p)
		inv.AppPools = append(inv.AppPools, p)
	}
	return inv, nil
}

func normaliseSource(s string) Source {
	switch strings.TrimSpace(s) {
	case "powershell-iisadmin":
		return SourcePowerShellIISAdmin
	case "powershell-webadmin":
		return SourcePowerShellWebAdmin
	}
	return SourceUnknown
}

func atoi(n json.Number) int {
	if n == "" {
		return 0
	}
	if v, err := n.Int64(); err == nil {
		return int(v)
	}
	if i, err := strconv.Atoi(n.String()); err == nil {
		return i
	}
	return 0
}

func unwrapSingletonArrays(in []byte) []byte {
	s := string(in)
	for _, key := range []string{`"sites":`, `"app_pools":`, `"bindings":`} {
		s = wrapSingletonValue(s, key)
	}
	return []byte(s)
}

func wrapSingletonValue(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(key):]
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i >= len(rest) || rest[i] != '{' {
		return s
	}
	depth, inStr, escaped := 0, false, false
	end := -1
	for j := i; j < len(rest); j++ {
		c := rest[j]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case c == '{' && !inStr:
			depth++
		case c == '}' && !inStr:
			depth--
			if depth == 0 {
				end = j + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= i {
		return s
	}
	wrapped := "[" + rest[i:end] + "]" + rest[end:]
	return s[:idx+len(key)] + wrapped
}

func trimUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
