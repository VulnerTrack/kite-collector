# install.ps1 - Install kite-collector on Windows
# Usage: irm https://get.kite-collector.dev/install.ps1 | iex
#
# This script:
#   1. Detects the system architecture
#   2. Downloads the latest kite-collector binary from GitHub Releases directly
#   3. Verifies SHA256 against the published release checksums
#   4. Installs to %ProgramFiles%\kite-collector\ and registers/starts the service
#      (-NoService explicitly installs only a user binary in %LOCALAPPDATA%)
#   5. Configures automatic startup and failure recovery
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
    [switch]$Service = $true,
    [switch]$NoService,
    [switch]$NoPath,
    [switch]$Osquery
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repo = "VulnerTrack/kite-collector"
$installDir = "$env:LOCALAPPDATA\kite-collector"
$installService = $Service -and -not $NoService
if ($installService) {
    # A LocalSystem service must not execute from a user-writable directory.
    $installDir = Join-Path $env:ProgramFiles "kite-collector"
}

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

if ($Osquery -and -not $installService) {
    throw "-Osquery installs machine services and cannot be combined with -NoService or -Service:`$false."
}
if ($installService -or $Osquery) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Automatic service installation requires Administrator PowerShell. Use -NoService only for a manual, binary-only installation."
    }
}

# ---------------------------------------------------------------------------
# Self-contained bundle path (-Osquery): one download, both services.
# ---------------------------------------------------------------------------
if ($Osquery) {
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

Write-Host "  Downloading $assetName..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$stagingDir = Join-Path $installDir (".install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stagingDir | Out-Null
$tmpPath = Join-Path $stagingDir $assetName
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpPath -UseBasicParsing
    $checksums = (Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/checksums.txt" -UseBasicParsing).Content
    $pattern = '^([a-fA-F0-9]{64})\s+\*?' + [regex]::Escape($assetName) + '$'
    $expected = @($checksums -split '\r?\n' | ForEach-Object {
        if ($_.Trim() -match $pattern) { $Matches[1].ToLowerInvariant() }
    })
    if ($expected.Count -ne 1) {
        throw "Release checksums do not contain exactly one SHA256 for $assetName."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmpPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected[0]) {
        throw "Checksum mismatch for $assetName; the installer was not executed."
    }

    if ($installService) {
        # Run the verified staging copy so the native installer can stop the
        # existing service before replacing its locked executable on upgrades.
        Write-Host "  Installing the automatic Windows service..."
        & $tmpPath install --binary-dir $installDir
        if ($LASTEXITCODE -ne 0) {
            throw "Service installation failed (exit $LASTEXITCODE). Fix the reported error and rerun this installer."
        }
    } else {
        Move-Item -Force -Path $tmpPath -Destination $binaryPath
        Write-Host "  Binary-only installation requested; no automatic service was registered."
    }
    & $binaryPath version
    if ($LASTEXITCODE -ne 0) {
        throw "Installed binary verification failed (exit $LASTEXITCODE)."
    }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $stagingDir
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

Write-Host ""
Write-Host "  Installed successfully: $binaryPath" -ForegroundColor Green
Write-Host ""

# Print getting-started instructions.
Write-Host "  Getting started:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    # One-time enrollment with your platform"
Write-Host "    kite-collector enroll --agent-code <code> --token <token>"
Write-Host ""
if (-not $installService) {
    Write-Host "    # Enable automatic collection from Administrator PowerShell"
    Write-Host "    kite-collector install"
} else {
    Write-Host "    # The service is running and starts automatically when Windows boots."
    Write-Host "    # Enrollment is required before inventory can be sent to your organization."
}
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
