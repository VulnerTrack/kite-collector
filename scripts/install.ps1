# install.ps1 - Install kite-collector on Windows
# Usage: irm https://get.kite-collector.dev/install.ps1 | iex
#
# This script:
#   1. Detects the system architecture
#   2. Downloads the latest kite-collector binary from GitHub Releases directly
#   3. Installs it to %LOCALAPPDATA%\kite-collector\
#   4. Adds the install directory to the user PATH
#   5. Optionally registers the Windows service when -Service is passed
#   6. Prints getting-started instructions

param(
    [switch]$Service,
    [switch]$NoService,
    [switch]$NoPath
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repo = "VulnerTrack/kite-collector"
$installDir = "$env:LOCALAPPDATA\kite-collector"

Write-Host ""
Write-Host "  kite-collector installer" -ForegroundColor Cyan
Write-Host "  =======================" -ForegroundColor Cyan
Write-Host ""

# Detect architecture. Releases currently publish windows/amd64 only.
if (-not [System.Environment]::Is64BitOperatingSystem) {
    Write-Host "  ERROR: kite-collector publishes Windows binaries for 64-bit Windows only." -ForegroundColor Red
    exit 1
}
$arch = "amd64"
Write-Host "  Architecture: windows/$arch"

# Download binary. The /latest/download URL redirects to the newest release
# asset and avoids a separate GitHub API request.
$assetName = "kite-collector_windows_${arch}_bin.exe"
$downloadUrl = "https://github.com/$repo/releases/latest/download/$assetName"
$binaryPath = "$installDir\kite-collector.exe"
$tmpPath = "$binaryPath.download"

Write-Host "  Downloading $assetName..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpPath -UseBasicParsing
    Move-Item -Force -Path $tmpPath -Destination $binaryPath
} catch {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpPath
    Write-Host "  ERROR: download failed from $downloadUrl" -ForegroundColor Red
    throw
}

# Add to PATH if not already present.
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathParts = @($userPath -split ';' | Where-Object { $_ })
    if ($pathParts -notcontains $installDir) {
        Write-Host "  Adding $installDir to user PATH..."
        $newUserPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        if (($env:Path -split ';') -notcontains $installDir) {
            $env:Path = "$env:Path;$installDir"
        }
    }
}

# Verify installation.
Write-Host ""
Write-Host "  Installed:" -ForegroundColor Green
& $binaryPath version
Write-Host ""

if ($Service -and -not $NoService) {
    # Windows service registration uses SCM and requires Administrator rights.
    Write-Host "  Registering kite-collector as a Windows service..."
    try {
        & $binaryPath install --binary-dir $installDir
    } catch {
        Write-Host "  WARNING: service registration failed: $_" -ForegroundColor Yellow
        Write-Host "  You can retry later from Administrator PowerShell with: kite-collector install" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Skipping service registration. Use -Service from Administrator PowerShell to register it."
}
Write-Host ""

# Print getting-started instructions.
Write-Host "  Getting started:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    # One-time enrollment with your platform"
Write-Host "    kite-collector enroll --agent-code <code> --token <token>"
Write-Host ""
Write-Host "    # Optional: register/start the continuous streaming service from Administrator PowerShell"
Write-Host "    kite-collector install"
Write-Host "    kite-collector service start"
Write-Host ""
Write-Host "    # Check service status"
Write-Host "    kite-collector service status"
Write-Host ""
Write-Host "    # One-off scan or interactive setup"
Write-Host "    kite-collector scan"
Write-Host "    kite-collector init"
Write-Host ""
Write-Host "    # Open dashboard in browser"
Write-Host "    kite-collector dashboard"
Write-Host ""
Write-Host "  To uninstall the service later:" -ForegroundColor Cyan
Write-Host "    kite-collector uninstall"
Write-Host ""
