# kite-collector

[Español](README.es.md)

Configuration Management Database (CMDB) agent for IT asset discovery.

A single binary that scans your network, inventories installed software, and captures the as-built configuration state of every host it observes. Discovery sources span cloud APIs, hypervisors, OS, network listeners, and dozens of config files (SSH, firewall, PAM, nsswitch, MongoDB, MySQL, …).

Results are stored in a local SQLite database. No servers, no dependencies, fully offline.

**Contents:** [Install](#install), [First scan](#first-scan), [What it discovers](#what-it-discovers), [Configuration](#configuration), [Commands](#commands), [Database](#database), [Dashboard](#dashboard), [Scan API](#scan-api), [Streaming to OpenTelemetry](#streaming-to-opentelemetry), [Security](#security)

## Install

### Quick install (Linux, macOS, FreeBSD, OpenBSD)

```bash
curl -fsSL https://raw.githubusercontent.com/VulnerTrack/kite-collector/main/installers/installer.sh | sh
sudo kite-collector enroll    # sign in; the service starts once enrolled
```

The script installs the collector and registers its background service
(enabled at boot; it starts once the host is enrolled), so signing in is the
only step left. It picks the native channel: the APT repository on
Debian/Ubuntu, the release `.rpm` on Fedora/RHEL/SUSE, and the static binary in
`/usr/local/bin` elsewhere, and checks every download against the release's
`checksums.txt`. On a host where the script could not register the service,
`sudo kite-collector install` alone registers it, signs in, and starts it.

Set these on the `sh` side of the pipe, for example
`curl -fsSL …/installer.sh | KITE_OSQUERY=no sh`:

| variable | effect |
|----------|--------|
| `KITE_VERSION=1.2.3` | pin a release |
| `KITE_OSQUERY=no` | plain collector, and keep it on re-runs, even where the bundle exists (`yes` requires the bundle) |
| `KITE_INSTALL_METHOD=binary` | force `apt`, `rpm` or `binary` |
| `KITE_INSTALL_DIR=$HOME/.local/bin` | binary target; a directory you can write needs no root |

### Ubuntu / Debian (APT repository)

```bash
curl -fsSL https://vulnertrack.github.io/kite-collector/repository.key \
  | sudo tee /usr/share/keyrings/kite-collector-keyring.asc > /dev/null
echo "deb [signed-by=/usr/share/keyrings/kite-collector-keyring.asc] https://vulnertrack.github.io/kite-collector/ stable main" \
  | sudo tee /etc/apt/sources.list.d/kite-collector.list
sudo apt update && sudo apt install kite-collector
sudo kite-collector enroll
```

The package ships and enables its own systemd unit, so enrolling is the only
step after `apt install`. The repository keeps the three most recent releases
of each package: `apt-cache policy kite-collector` lists them and
`sudo apt install kite-collector=1.2.3` pins or rolls back. Older releases stay
on the [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases)
page.

### Fedora, RHEL, SUSE, Arch

- **Fedora / RHEL / SUSE:** the quick install uses the release `.rpm`. To do it
  by hand, download it from
  [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) and
  run `sudo dnf install ./kite-collector-*.rpm`.
- **Arch:** install from the signed pacman repository with
  `sudo pacman -Syu kite-collector` after adding it as described in
  [packaging/pacman/README.md](packaging/pacman/README.md#client-install).

### Snap

```bash
sudo snap install kite-collector
sudo kite-collector install
sudo kite-collector enroll
```

snapd manages the binary, service, and updates; `install` prepares persistent
storage under `/var/snap/kite-collector/common/certs`, and `enroll` enables
and starts the service. Check the service with `snap services kite-collector`
and follow its logs with `sudo snap logs -f kite-collector.kite-collector-daemon`.

### macOS (Homebrew)

```bash
brew install --cask vulnertrack/tap/kite-collector
sudo kite-collector install   # registers launchd against the brew-managed binary — no second copy
```

The cask clears the Gatekeeper quarantine attribute, so the binary runs without
the "unidentified developer" prompt. `brew upgrade --cask kite-collector` is all
an upgrade takes: the running service notices the new binary and restarts onto
it. Run `sudo kite-collector uninstall` before `brew uninstall`, because the
cask removes the launchd job only on `brew uninstall --zap`.

### Windows

Download `kite-collector_<version>_amd64.msi` from
[GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) and
double-click it, or deploy it silently (GPO/Intune) as an administrator:

```powershell
msiexec /i kite-collector_<version>_amd64.msi /quiet
```

Other ways to install:

| Method | How |
| ------ | --- |
| GUI wizard | Double-click `kite-collector_windows_amd64_bin.exe`; it detects the double-click and opens the installer |
| PowerShell | `irm https://get.kite-collector.dev/install.ps1 \| iex` |
| PowerShell, binary only (no service) | `& ([scriptblock]::Create((irm https://get.kite-collector.dev/install.ps1))) -NoService` |
| WinGet | `winget install VulnerTrack.KiteCollector` |
| Scoop | `scoop bucket add vulnertrack https://github.com/VulnerTrack/homebrew-tap` then `scoop install kite-collector` |

Step-by-step guides: [docs/windows-quickstart.md](docs/windows-quickstart.md)
and [docs/window_install.md](docs/window_install.md). Windows 7 SP1 and
Windows 8 computers need the isolated 32-bit legacy build:
[legacy/windows7/README.md](legacy/windows7/README.md).

### Adding osquery

| Platform | How |
| -------- | --- |
| Debian / Ubuntu amd64 | The quick install picks `kite-collector-osquery` by default; with apt, `sudo apt install kite-collector-osquery` |
| Windows | `kite-collector-osquery_<version>_amd64.msi` ([details](docs/window_install.md#bundled-osquery-msi-kite-collector-osquery)) |
| macOS | `brew install --cask osquery`, then `sudo kite-collector install --with-osquery` ([details](docs/macos-osquery.md)) |

On Linux and Windows the bundle is the same agent plus an osqueryd running as
the `kite-osqueryd` service. It is namespaced under kite's own paths, so it
never conflicts with a standalone osquery install, and the collector's osquery
source finds its socket on its own. The two Debian packages replace each other
on install.

macOS has no bundle. kite adopts the osquery you already have, because a
vendored osqueryd would have to run under kite's signature and Full Disk Access
grant. If you run osquery's own daemon instead (`sudo osqueryctl start`),
discovery detects it with no kite-side setup. Without Full Disk Access,
osqueryd reads TCC-protected paths as *empty rather than failing*; read
[docs/macos-osquery.md](docs/macos-osquery.md) before trusting a clean result.

### Manual download and build from source

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64.tar.gz | tar xz

# macOS
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_darwin_arm64.tar.gz | tar xz

# From source
make build

# Cross-compile for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o bin/kite-collector.exe ./cmd/kite-collector
```

### Upgrades and removal

When a package manager (Homebrew, apt, dnf, pacman) put the binary on your
system, `kite-collector install` registers the service against the
package-managed path instead of copying it. A package upgrade then restarts the
service onto the new version; the agent notices its binary changed on disk and
relaunches, waiting for any running scan to finish first.

- `install --copy` forces a copy into the service path.
- `install --repair` cleans up a service that drifted onto a stale copy
  (`kite-collector doctor` tells you when that's the case).
- `uninstall --purge` also removes the data directory.

### Mass deployment

The dashboard's **Mass deployment** page discovers computers on the local
network and generates one short-lived Ansible package that installs and enrolls
collectors on Windows, Linux, and macOS targets, with a single-use enrollment
credential per computer. Windows targets need WinRM enabled first. The
walkthrough and the WinRM preparation command are in
[docs/mass-deployment.md](docs/mass-deployment.md).

## First scan

```bash
kite-collector status                          # installed, enrolled, healthy?
kite-collector scan                            # scan this host (no config needed)
kite-collector scan --scope 192.168.1.0/24     # scan a subnet
kite-collector scan --source docker            # include Docker containers
kite-collector scan --output json              # table (default), json, or csv
kite-collector dashboard                       # browse the results
kite-collector agent --stream --interval 6h    # continuous monitoring
```

When something looks wrong, `kite-collector doctor` says why and what to run
next.

## What it discovers

| Source          | Assets                                               | Auth Required          |
| --------------- | ---------------------------------------------------- | ---------------------- |
| Local agent     | Hostname, OS, interfaces, installed packages         | No                     |
| Network scan    | Reachable hosts via TCP connect                      | No                     |
| Docker / Podman | Containers, images, networks                         | Socket access          |
| UniFi           | Clients (VLAN, switch port, signal), network devices | Controller credentials |
| AWS EC2         | EC2 instances across regions                         | IAM credentials        |
| GCP Compute     | Compute Engine VMs                                   | ADC                    |
| Azure           | Virtual machines across subscriptions                | Service principal      |
| Proxmox         | VMs and LXC containers                               | API token              |
| SNMP            | Switches, routers, UPS devices                       | Community string       |

These are the common sources. Every source, with the credentials it needs, is
listed in [configs/kite-collector.example.yaml](configs/kite-collector.example.yaml).

### Configuration checks

For every host, the agent records:

| Check              | What it records                                            |
| ------------------ | ---------------------------------------------------------- |
| SSH config         | `PermitRootLogin`, `PasswordAuthentication`, ciphers, MACs |
| Firewall           | iptables / nftables / ufw rule tables                      |
| Kernel             | ASLR setting, kernel command line, loaded modules          |
| File permissions   | `/etc/shadow`, `/etc/sudoers`, world-readable secrets      |
| Listening services | Open TCP/UDP ports per process                             |
| Database listeners | Postgres / MySQL / MongoDB bind addresses                  |

These observations land in the CMDB as inventory data. kite-collector reports the configuration state and does not score it against a vulnerability taxonomy.

### Software inventory

The agent reads installed packages from OS package managers (dpkg, rpm, dnf,
zypper, pacman, apk, xbps, portage, nix, Homebrew, MacPorts, Flatpak, Snap, the
Windows registry, WinGet, Chocolatey, Scoop, …) and language ecosystems (npm,
pip, Cargo, Go modules, Maven, NuGet, RubyGems, Composer, Conda, …). Each
package gets a [CPE 2.3](https://nvd.nist.gov/products/cpe) identifier so
downstream tools (your SIEM, CMDB, vulnerability scanner) can correlate the
inventory against their own data.

## Configuration

kite-collector runs without a config file. To change its behavior, create a YAML config:

```yaml
discovery:
  sources:
    agent:
      enabled: true
      collect_software: true
    network:
      enabled: true
      scope: [192.168.1.0/24]
      tcp_ports: [22, 80, 443, 3389, 8080, 8443]
    docker:
      enabled: true
      host: unix:///var/run/docker.sock
    unifi:
      enabled: true
      endpoint: https://192.168.1.1:8443
      site: default

classification:
  authorization:
    allowlist_file: ./configs/authorized-machines.yaml
    match_fields: [hostname]

audit:
  enabled: true

stale_threshold: 168h # 7 days
```

Environment variables override config with `KITE_` prefix (e.g. `KITE_LOG_LEVEL=debug`).

See `configs/kite-collector.example.yaml` for all options.

## Commands

| Command          | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| `install`        | Install as a service and sign in (`--agent-code` + `--token` for headless) |
| `uninstall`      | Remove the service                                              |
| `enroll`         | Enroll with VulnerTrack (browser, sign-in code, or scoped token) |
| `unenroll`       | Remove the local enrollment                                     |
| `scan`           | One-shot discovery + configuration audit (`--detect` probes only) |
| `agent --stream` | Continuous mode with configurable interval                      |
| `service`        | Start/stop/restart/status of the installed service              |
| `status`         | Agent state at a glance (`--json` for scripts)                  |
| `doctor`         | Staged diagnostics with remediation hints (alias: `check`)      |
| `dashboard`      | Browser-based local UI — data exploration lives here            |
| `fleet`          | Discover computers and deploy collectors                        |
| `integrations`   | List and configure services connected to Kite                   |
| `version`        | Print version, commit, build date                               |

Older commands (`stream`, `query`, `db`, `diff`, `report`, …) still run but are
hidden from help, and each prints its replacement when invoked.

## Asset classification

Every discovered asset is classified on two axes:

**Authorization** (is this asset supposed to be here?):

- `unknown`: default, not yet evaluated
- `authorized`: matches an entry in the allowlist
- `unauthorized`: explicitly not in the allowlist

**Managed state** (does this asset meet our security controls?):

- `unknown`: default, controls not configured
- `managed`: all required controls present
- `unmanaged`: missing one or more required controls

Assets never default to `authorized`. Only positive matches against your source of truth produce `authorized`.

## Database

All results are stored in a SQLite file, `kite.db`, encrypted at rest with a
key derived from the agent identity. A one-shot `scan` writes `./kite.db`; the
installed service keeps it in its data directory, and `kite-collector status`
prints the path. Browse and export its tables from the dashboard at
<http://127.0.0.1:9090/tables>, or query the decrypted working copy with
`sqlite3` while kite-collector has it open:
[docs/sqlite-cheatsheet.md](docs/sqlite-cheatsheet.md).

## Platform integration

kite-collector can feed into the [Vulnertrack Intelligence Engine](https://github.com/VulnerTrack/vulnertrack-intelligence-engine) so its inventory becomes the source of truth for downstream tools:

```bash
# Import scan results into ClickHouse
vie kite scan --scope 192.168.1.0/24 --import

# Query imported assets
vie kite assets --authorized unauthorized
```

## Dashboard

`kite-collector dashboard` serves the local UI. Its start banner prints the URLs
that reach it, each labelled **this machine**, **local network**, or
**public**, so you can tell from the banner whether it is exposed. Container
and VM bridge addresses are counted rather than listed. Under
`kite-collector agent --dashboard-addr` the same URLs appear in the start log.

- **Containers** — a live view of local Docker / Podman / Compose containers
  with CPU and memory graphs and image history:
  [docs/container-observability.md](docs/container-observability.md).
- **Volumes** — capacity, inode pressure and encryption posture of every
  mounted filesystem across the fleet:
  [docs/storage-observability.md](docs/storage-observability.md).

## Scan API

In long-lived mode (`kite-collector agent`), the agent serves a REST API that
triggers, follows (Server-Sent Events) and cancels scans; the dashboard uses
the same endpoints. It listens on `127.0.0.1:8080` by default (`api.addr`).
Set `fleet.api_key` before binding it to another address; without a key the
API is unauthenticated. Only one scan runs at a time. Reference:
[docs/scan-api.md](docs/scan-api.md).

## Streaming to OpenTelemetry

kite-collector pushes machine lifecycle events to any OTLP-compatible collector
(Grafana Alloy, OpenTelemetry Collector, Datadog Agent, etc.) as OTLP log
records over HTTP/JSON:

```yaml
streaming:
  interval: 6h
  otlp:
    endpoint: http://localhost:4318
    protocol: http
```

```bash
kite-collector agent --stream --interval 6h
```

- Event attributes and types: [docs/telemetry-contract.md](docs/telemetry-contract.md)
- mTLS, payload signing and encryption, retries:
  [docs/otlp-streaming.md](docs/otlp-streaming.md)
- A runnable collector with Docker Compose:
  [examples/streaming-to-otel/](examples/streaming-to-otel/)

## Security

- **Read-only**: never writes to, modifies, or executes code on discovered systems
- **Dedicated credential storage**: connector passwords never enter SQLite or YAML; Kite uses the operating-system credential store when available and an identity-key encrypted AES-256-GCM store on headless hosts
- **Structured logging**: `log/slog` JSON output with automatic credential redaction
- **Minimal privileges**: works as non-root with graceful degradation for permission-denied paths

## License

MIT, see [LICENSE](LICENSE).
