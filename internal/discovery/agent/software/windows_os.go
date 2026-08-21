package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// WindowsOS inventories Windows itself and its activation/license state.
// Unlike winget and Chocolatey, PowerShell is present on every supported
// Windows installation, so this record is not dependent on a package manager.
type WindowsOS struct{}

func NewWindowsOS() *WindowsOS    { return &WindowsOS{} }
func (w *WindowsOS) Name() string { return "windows-os" }
func (w *WindowsOS) Available() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	_, err := exec.LookPath("powershell.exe")
	return err == nil
}

const windowsOSInventoryScript = `$ErrorActionPreference = 'Stop'
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$lic = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
  Where-Object { $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' -and $_.PartialProductKey } |
  Sort-Object LicenseStatus -Descending | Select-Object -First 1
[pscustomobject]@{
  name = if ($cv.ProductName) { [string]$cv.ProductName } elseif ($os.Caption) { [string]$os.Caption } else { 'Microsoft Windows' }
  version = if ($cv.DisplayVersion) { [string]$cv.DisplayVersion } else { [string]$os.Version }
  build = if ($cv.CurrentBuild) { [string]$cv.CurrentBuild } else { [string]$os.BuildNumber }
  architecture = [string]$os.OSArchitecture
  edition = [string]$cv.EditionID
  license_status = if ($lic) { [int]$lic.LicenseStatus } else { -1 }
} | ConvertTo-Json -Compress`

type windowsOSPayload struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Build         string `json:"build"`
	Architecture  string `json:"architecture"`
	Edition       string `json:"edition"`
	LicenseStatus int    `json:"license_status"`
}

func (w *WindowsOS) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Bypass", "-Command", windowsOSInventoryScript)
	if err != nil {
		return nil, fmt.Errorf("collect Windows OS inventory: %w", err)
	}
	return ParseWindowsOSOutput(out)
}

// ParseWindowsOSOutput maps Microsoft's LicenseStatus values to an explicit
// inventory value. Status 1 is Licensed; every known non-zero/non-licensed
// state (grace, notification, extended grace) is not fully licensed.
func ParseWindowsOSOutput(out []byte) (*Result, error) {
	var raw windowsOSPayload
	clean := strings.TrimPrefix(strings.TrimSpace(string(out)), "\ufeff")
	if err := json.Unmarshal([]byte(clean), &raw); err != nil {
		return nil, fmt.Errorf("decode Windows OS inventory: %w", err)
	}
	name := strings.TrimSpace(raw.Name)
	if name == "" {
		name = "Microsoft Windows"
	}
	version := strings.TrimSpace(raw.Version)
	if build := strings.TrimSpace(raw.Build); build != "" && !strings.Contains(version, build) {
		if version == "" {
			version = build
		} else {
			version += " (build " + build + ")"
		}
	}
	license := "unknown"
	if raw.LicenseStatus == 1 {
		license = "licensed"
	} else if raw.LicenseStatus >= 0 {
		license = "unlicensed"
	}
	description := "Windows operating system"
	if edition := strings.TrimSpace(raw.Edition); edition != "" {
		description += "; edition " + edition
	}
	item := model.InstalledSoftware{
		ID: uuid.Must(uuid.NewV7()), SoftwareName: name, Vendor: "Microsoft",
		Version: version, Architecture: strings.TrimSpace(raw.Architecture),
		PackageManager: "windows-os", License: license, Description: description,
	}
	item.CPE23 = BuildCPE23(item.Vendor, item.SoftwareName, version)
	return &Result{Items: []model.InstalledSoftware{item}}, nil
}

var _ Collector = (*WindowsOS)(nil)
