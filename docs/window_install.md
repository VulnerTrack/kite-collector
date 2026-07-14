# Installing kite-collector on Windows

This guide covers installing kite-collector as a managed Windows service. The
service runs continuous asset discovery in the background and streams events
to your OTLP collector, restarting automatically on failure or boot.

The service is registered through the Windows Service Control Manager (SCM)
via the [kardianos/service](https://github.com/kardianos/service) library —
the same install command works identically on Linux (systemd) and macOS
(launchd).

## TL;DR — one-liner installer

Open PowerShell and run:

```powershell
irm https://get.kite-collector.dev/install.ps1 | iex
```

This is self-contained: it downloads the binary, adds it to your PATH, and
registers a **per-user** Windows service. No elevation required.

For the fastest binary-only install, skip service registration:

```powershell
& ([scriptblock]::Create((irm https://get.kite-collector.dev/install.ps1))) -NoService
```

After it finishes:

```powershell
kite-collector install --agent-code <code>   # sign in with Vulnertrack in the browser
kite-collector service start --user
kite-collector service status --user
```

## What the installer does

`install.ps1` performs five steps:

1. Verifies that the host is 64-bit Windows (`amd64`).
2. Downloads the latest `kite-collector_windows_amd64_bin.exe` asset directly
   from the GitHub Releases `latest/download` URL, avoiding a separate API
   request.
3. Downloads it to `%LOCALAPPDATA%\kite-collector\kite-collector.exe`.
4. Appends that directory to the **user** `Path` environment variable.
5. Runs `kite-collector.exe install --user --binary-dir %LOCALAPPDATA%\kite-collector`
   which registers the per-user `kite-collector` Windows service pointing at
   the downloaded executable.

## Choosing system vs. user install

| Scope | Privilege | Service runs as | Best for |
| --- | --- | --- | --- |
| **User** (default in `install.ps1`) | Standard user | Your logged-in user | Workstations, laptops, dev machines |
| **System** | Administrator | `LocalSystem` | Servers, shared endpoints, fleet-managed boxes |

### User install (no elevation needed)

```powershell
kite-collector install --user
```

The service is registered against your user account and is visible only when
you are logged in. It is the right choice if the kite-collector binary lives
under `%LOCALAPPDATA%`.

### System install (Administrator)

Open an **elevated** PowerShell (Run as Administrator), then:

```powershell
kite-collector install
```

This registers the service against the SCM as `LocalSystem`. Default paths:

- Binary: `%ProgramFiles%\kite-collector\kite-collector.exe`
- Certificate store: `%ProgramData%\kite-collector`

## Direct graphical setup

If you prefer not to run the one-liner:

1. Download `kite-collector_windows_amd64_bin.exe` from
   [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases).
2. Rename it to `kite-collector.exe`.
3. Double-click it to open the graphical setup.

Use the direct `.exe` asset for this flow, not the `.tar.gz` archive. Running
an executable from inside a compressed archive causes Windows to show an
extra extraction warning before setup opens.

## Manual install from PowerShell

For scripted installs, place `kite-collector.exe` in a stable directory and
run:

```powershell
# System install
kite-collector.exe install --binary-dir "C:\Program Files\kite-collector"

# Or user install
kite-collector.exe install --user --binary-dir "$env:LOCALAPPDATA\kite-collector"
```

## Install flags

```text
kite-collector install [flags]

Flags:
      --user                install as a per-user service (no Administrator needed)
      --certs-dir string    certificate store path (default: OS-appropriate)
      --binary-dir string   directory to install the binary (default: OS-appropriate)
      --config string       path to configuration file to pass to the service
      --db string           path to SQLite database file to pass to the service
      --endpoint string     OTLP endpoint override to pass to the service
  -v, --verbose             run the service with debug logging
      --dry-run             print what would be done without making any changes
```

Use `--dry-run` first if you want to inspect the planned changes — it prints
the binary copy target, the certs directory, and the exact service config
that will be registered with SCM.

## Managing the service

All control commands work in both modes; pass `--user` for per-user services.

```powershell
kite-collector service start    --user   # start the service
kite-collector service stop     --user   # stop the service
kite-collector service restart  --user   # stop + start
kite-collector service status   --user   # prints: running | stopped | not installed | unknown
```

You can also use Windows-native tools:

```powershell
# View the service in SCM
Get-Service kite-collector

# Or via sc.exe
sc.exe query kite-collector
sc.exe start kite-collector
sc.exe stop  kite-collector
```

## First-time enrollment

Before the service can stream anything useful, enroll the agent by re-running
install with your agent code — it prints a sign-in URL; open it in any
browser, approve the collector, and paste the code back (or pass
`--token pki_enroll_v1_...` to use a legacy enrollment token instead):

```powershell
kite-collector install --agent-code <code>
```

This writes mTLS material into the certificate store (`%LOCALAPPDATA%\kite-collector\data\`
for user installs, `%ProgramData%\kite-collector\` for system installs). The
service auto-detects the certs at the path it was installed with and switches
to mTLS for OTLP delivery on the next restart.

Verify connectivity:

```powershell
kite-collector check
```

Then start the service:

```powershell
kite-collector service start --user
```

## Viewing logs

The service writes to the Windows Event Log under the `kite-collector` source.

```powershell
# Newest 50 events
Get-EventLog -LogName Application -Source kite-collector -Newest 50

# Tail like journalctl -f (PowerShell 5+)
Get-WinEvent -LogName Application -FilterXPath "*[System/Provider/@Name='kite-collector']" -MaxEvents 20
```

For higher-volume troubleshooting, reinstall with `--verbose` so the service
emits debug-level structured logs.

## Uninstalling

```powershell
# Stops the service (if running) and removes the SCM registration.
# Match the mode the service was installed with.
kite-collector uninstall --user      # per-user service
kite-collector uninstall              # system service (requires Administrator)
```

The installed binary and certificate store are intentionally **left in
place**. Remove them manually if desired:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\kite-collector"
# system:
Remove-Item -Recurse -Force "$env:ProgramFiles\kite-collector"
Remove-Item -Recurse -Force "$env:ProgramData\kite-collector"
```

## File locations

| Item | User install | System install |
| --- | --- | --- |
| Binary | `%LOCALAPPDATA%\kite-collector\kite-collector.exe` | `%ProgramFiles%\kite-collector\kite-collector.exe` |
| Certificate store | `%LOCALAPPDATA%\kite-collector\data\` | `%ProgramData%\kite-collector\` |
| Service name (SCM) | `kite-collector` | `kite-collector` |
| Service display name | Kite Collector | Kite Collector |
| Logs | Windows Event Log → Application → kite-collector | Same |

## Troubleshooting

### `install` fails with `Access is denied`

You're trying a system install without elevation. Either re-launch PowerShell
as Administrator, or use `--user`.

### Service registers but won't start

Check the Event Log:

```powershell
Get-EventLog -LogName Application -Source kite-collector -Newest 20
```

The most common cause is `kite-collector.exe` being moved after install. The
service's `ImagePath` in SCM is fixed at install time — if you moved the
binary, `uninstall` then `install` again from the new location.

### `kite-collector is not recognized`

The installer adds `%LOCALAPPDATA%\kite-collector` to the **user** `Path`,
but the change applies to new shells only. Close and reopen PowerShell, or
update the current session:

```powershell
$env:Path += ";$env:LOCALAPPDATA\kite-collector"
```

### Service status shows `not installed`

You're querying the opposite scope from where you installed. A per-user
install is invisible to `kite-collector service status` (without `--user`)
and vice versa.

```powershell
kite-collector service status           # checks system scope
kite-collector service status --user    # checks user scope
```

### Need to switch from user to system install

```powershell
# As the user who installed it:
kite-collector uninstall --user

# As Administrator:
kite-collector install
```

## See also

- [Windows quickstart](windows-quickstart.md) — non-service workflows
  (`scan`, `init`, `dashboard`) on Windows.
- [`scripts/install.ps1`](../scripts/install.ps1) — source of the one-liner
  installer.
- [`cmd/kite-collector/install.go`](../cmd/kite-collector/install.go) —
  cross-platform service registration logic.
