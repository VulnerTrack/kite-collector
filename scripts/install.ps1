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
#
# -Osquery (RFC-0156) switches to the self-contained installer,
# kite-collector-osquery_windows_amd64.exe: one download that installs both the
# collector and a checksum-verified osqueryd 5.15.0 as the kite-osqueryd
# service, enabling FIM/YARA discovery. Before this switch existed the only
# Windows path to osquery-backed discovery was finding the right MSI by hand
# and hoping msiexec was not blocked by policy — this script had no awareness
# of it at all.
#
# The bundle download is SHA256-verified against its published sidecar and runs
# elevated (it writes Program Files, HKLM and two service registrations), so
# -Osquery must be run from an Administrator PowerShell.

param(
    [switch]$Service,
    [switch]$NoService,
    [switch]$NoPath,
    [switch]$Osquery
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

# ---------------------------------------------------------------------------
# Self-contained bundle path (-Osquery): one download, both services.
# ---------------------------------------------------------------------------
if ($Osquery) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  ERROR: -Osquery installs two machine services and must run from an" -ForegroundColor Red
        Write-Host "         Administrator PowerShell." -ForegroundColor Red
        exit 1
    }

    $bundleAsset = "kite-collector-osquery_windows_${arch}.exe"
    $bundleUrl = "https://github.com/$repo/releases/latest/download/$bundleAsset"
    $bundlePath = Join-Path $env:TEMP $bundleAsset

    Write-Host "  Downloading $bundleAsset (collector + osqueryd)..."
    try {
        Invoke-WebRequest -Uri $bundleUrl -OutFile $bundlePath -UseBasicParsing
    } catch {
        Write-Host "  ERROR: download failed from $bundleUrl" -ForegroundColor Red
        throw
    }

    # Fail closed on the published checksum. The installer runs elevated and
    # registers a LocalSystem service, so "we could not verify it, carry on"
    # is not an acceptable outcome here.
    try {
        $expected = ((Invoke-WebRequest -Uri "$bundleUrl.sha256" -UseBasicParsing).Content `
            -split '\s+')[0].Trim().ToLower()
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $bundlePath
        Write-Host "  ERROR: could not fetch $bundleAsset.sha256 — refusing to run an" -ForegroundColor Red
        Write-Host "         unverified elevated installer." -ForegroundColor Red
        throw
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $bundlePath).Hash.ToLower()
    if ($actual -ne $expected) {
        Remove-Item -Force -ErrorAction SilentlyContinue $bundlePath
        Write-Host "  ERROR: checksum mismatch for $bundleAsset" -ForegroundColor Red
        Write-Host "         expected $expected" -ForegroundColor Red
        Write-Host "         actual   $actual" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Verified SHA256: $actual" -ForegroundColor Green

    Write-Host "  Running the self-contained installer..."
    $proc = Start-Process -FilePath $bundlePath -ArgumentList "/SILENT" -Wait -PassThru -NoNewWindow
    Remove-Item -Force -ErrorAction SilentlyContinue $bundlePath
    if ($proc.ExitCode -ne 0) {
        Write-Host "  ERROR: installer exited with code $($proc.ExitCode)." -ForegroundColor Red
        Write-Host "         See $env:ProgramData\kite-collector\install.log" -ForegroundColor Red
        exit $proc.ExitCode
    }

    Write-Host ""
    Write-Host "  Installed:" -ForegroundColor Green
    Write-Host "    kite-collector  (service)"
    Write-Host "    kite-osqueryd   (service, FIM/YARA discovery)"
    Write-Host "    install log     $env:ProgramData\kite-collector\install.log"
    Write-Host ""
    Write-Host "  Next: enroll this collector, then open the dashboard:" -ForegroundColor Cyan
    Write-Host "    kite-collector enroll"
    Write-Host "    kite-collector dashboard"
    Write-Host ""
    exit 0
}

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
Write-Host "  Want file-integrity + YARA discovery?" -ForegroundColor Cyan
Write-Host "    Re-run this script with -Osquery from an Administrator PowerShell."
Write-Host "    It downloads one self-contained installer that also registers"
Write-Host "    osqueryd as the kite-osqueryd service. No msiexec, no second download."
Write-Host ""
Write-Host "  To uninstall the service later:" -ForegroundColor Cyan
Write-Host "    kite-collector uninstall"
Write-Host ""
