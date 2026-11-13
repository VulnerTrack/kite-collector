# Hermetic installer checks for Linux PowerShell containers, without downloads
# or service registration. The Windows administrator probe is replaced in
# memory; native SCM behavior still needs a Windows release smoke test.
# Run: pwsh -NoProfile -File scripts/test-install.ps1
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsLinux) { throw "Run these isolated checks in a Linux PowerShell container." }

$installer = Join-Path $PSScriptRoot "install.ps1"
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$source = Get-Content -Raw $installer
$adminPattern = '\(\[Security\.Principal\.WindowsPrincipal\][\s\S]*?::Administrator\)'
if ([regex]::Matches($source, $adminPattern).Count -ne 1) {
    throw "The installer administrator probe changed; update the test seam."
}

$fakeBinary = @'
#!/bin/sh
printf '%s\n' "$1" >> "$KITE_TEST_COMMANDS"
if [ "$1" = install ]; then
    [ "$KITE_TEST_INSTALL_FAIL" = 1 ] && exit 17
    cp "$0" "$3/kite-collector.exe"
    chmod +x "$3/kite-collector.exe"
fi
if [ "$1" = version ] && [ "$KITE_TEST_VERSION_FAIL" = 1 ]; then exit 18; fi
exit 0
'@

function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    $script:downloadCount++
    if ($OutFile) {
        [IO.File]::WriteAllText($OutFile, $fakeBinary)
        & chmod +x $OutFile
        $script:binaryHash = (Get-FileHash -Algorithm SHA256 $OutFile).Hash.ToLowerInvariant()
        return
    }
    $hash = if ($script:badChecksum) { '0' * 64 } else { $script:binaryHash }
    return [pscustomobject]@{ Content = "$hash  kite-collector_windows_amd64_bin.exe`n" }
}

function Assert-InstallerCase {
    param([string]$Name, [hashtable]$Arguments, [bool]$Admin = $true,
        [bool]$InstallFails = $false, [bool]$BadHash = $false,
        [bool]$VersionFails = $false, [string]$ExpectedError = '',
        [string[]]$ExpectedCommands = @())
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
    $env:ProgramFiles = Join-Path $testRoot 'Program Files'
    $env:LOCALAPPDATA = Join-Path $testRoot 'User Data'
    $env:KITE_TEST_COMMANDS = Join-Path $testRoot 'commands'
    $env:KITE_TEST_INSTALL_FAIL = if ($InstallFails) { '1' } else { '0' }
    $env:KITE_TEST_VERSION_FAIL = if ($VersionFails) { '1' } else { '0' }
    $script:badChecksum = $BadHash
    $script:downloadCount = 0
    $adminValue = if ($Admin) { '$true' } else { '$false' }
    $scriptBlock = [scriptblock]::Create([regex]::Replace($source, $adminPattern, $adminValue))
    try {
        $caught = ''
        try { & $scriptBlock -NoPath @Arguments *>&1 | Out-Null }
        catch { $caught = $_.Exception.Message }
        if ($ExpectedError) {
            if ($caught -notlike "*$ExpectedError*") { throw "${Name}: expected '$ExpectedError', got '$caught'" }
        } elseif ($caught) { throw "${Name}: $caught" }
        $commands = if (Test-Path $env:KITE_TEST_COMMANDS) { @(Get-Content $env:KITE_TEST_COMMANDS) } else { @() }
        if (($commands -join ',') -ne ($ExpectedCommands -join ',')) {
            throw "${Name}: unexpected native commands: $($commands -join ',')"
        }
        if (-not $Admin -and -not $Arguments.NoService -and $script:downloadCount) {
            throw "${Name}: downloaded before checking Administrator rights"
        }
        if ((Test-Path $testRoot) -and @(Get-ChildItem $testRoot -Recurse -Directory -Force -Filter '.install-*').Count) {
            throw "${Name}: staging directory was not cleaned up"
        }
        Write-Host "PASS $Name"
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $testRoot
    }
}

Assert-InstallerCase 'default installs and starts the system service' @{} -ExpectedCommands @('install', 'version')
Assert-InstallerCase 'explicit binary-only opt-out' @{ NoService = $true } -Admin $false -ExpectedCommands @('version')
Assert-InstallerCase 'legacy Service false opt-out' @{ Service = $false } -ExpectedCommands @('version')
Assert-InstallerCase 'administrator required before downloading' @{} -Admin $false -ExpectedError 'requires Administrator'
Assert-InstallerCase 'native install failure is fatal' @{} -InstallFails $true -ExpectedError 'Service installation failed' -ExpectedCommands @('install')
Assert-InstallerCase 'checksum failure prevents execution' @{} -BadHash $true -ExpectedError 'Checksum mismatch'
Assert-InstallerCase 'native version failure is fatal' @{} -VersionFails $true -ExpectedError 'verification failed' -ExpectedCommands @('install', 'version')
