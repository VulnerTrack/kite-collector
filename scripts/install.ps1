# install.ps1 — Install kite-collector on Windows
# Usage: irm https://get.kite-collector.dev/install.ps1 | iex
#
# This script:
#   1. Detects the system architecture
#   2. Downloads the latest kite-collector binary from GitHub Releases
#   3. Installs it to %LOCALAPPDATA%\kite-collector\
#   4. Adds the install directory to the user PATH
#   5. Prints getting-started instructions

$ErrorActionPreference = "Stop"

$repo = "VulnerTrack/kite-collector"
$installDir = "$env:LOCALAPPDATA\kite-collector"

Write-Host ""
Write-Host "  kite-collector installer" -ForegroundColor Cyan
Write-Host "  =======================" -ForegroundColor Cyan
Write-Host ""

# Detect architecture.
$arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
Write-Host "  Architecture: windows/$arch"

# Determine latest release tag.
Write-Host "  Fetching latest release..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
$tag = $release.tag_name
Write-Host "  Latest version: $tag"

# Download binary.
$assetName = "kite-collector_windows_$arch.exe"
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    Write-Host "  ERROR: Asset $assetName not found in release $tag" -ForegroundColor Red
    exit 1
}

$downloadUrl = $asset.browser_download_url
$binaryPath = "$installDir\kite-collector.exe"

Write-Host "  Downloading $assetName..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath

# Add to PATH if not already present.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    Write-Host "  Adding $installDir to user PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    $env:Path = "$env:Path;$installDir"
}

# Verify installation.
Write-Host ""
Write-Host "  Installed:" -ForegroundColor Green
& $binaryPath version
Write-Host ""

# Print getting-started instructions.
Write-Host "  Getting started:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    # Scan this computer"
Write-Host "    kite-collector scan"
Write-Host ""
Write-Host "    # Interactive setup wizard"
Write-Host "    kite-collector init"
Write-Host ""
Write-Host "    # Open dashboard in browser"
Write-Host "    kite-collector dashboard"
Write-Host ""
Write-Host "    # Or just double-click kite-collector.exe!"
Write-Host ""
