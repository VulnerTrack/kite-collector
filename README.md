# kite-collector

Configuration Management Database (CMDB) agent for IT asset discovery.

A single binary that scans your network, inventories installed software, and captures the as-built configuration state of every host it observes. Discovery sources span cloud APIs, hypervisors, OS, network listeners, and dozens of config files (SSH, firewall, PAM, nsswitch, MongoDB, MySQL, …).

Results are stored in a local SQLite database. No servers, no dependencies, fully offline.

## Install

> **One owner per artifact.** When a package manager (Homebrew, apt, dnf,
> pacman) put the binary on your system, `kite-collector install` detects
> that and registers the service **against the package-managed path instead
> of copying** — so package upgrades restart the service onto the new
> version automatically (the agent notices its binary changed on disk and
> relaunches itself, waiting for any running scan to finish first). Pass
> `--copy` to force the old copy behavior, `--repair` to clean up an
> installation where the service drifted onto a stale copy (`kite-collector
> doctor` tells you when that's the case), and `uninstall --purge` to also
> remove the data directory. The deb/rpm packages ship their own systemd
> unit, so on those systems `install` only enrolls and enables it.

### Ubuntu / Debian (APT Repository)

You can install `kite-collector` on Debian-based distributions (such as Ubuntu, Linux Mint, or Pop!_OS) using the official APT repository:

1. Download and install the public keyring:
   ```bash
   curl -fsSL https://vulnertrack.github.io/kite-collector/repository.key | sudo tee /usr/share/keyrings/kite-collector-keyring.asc > /dev/null
   ```

2. Add the repository to your system sources:
   ```bash
   echo "deb [signed-by=/usr/share/keyrings/kite-collector-keyring.asc] https://vulnertrack.github.io/kite-collector/ stable main" | sudo tee /etc/apt/sources.list.d/kite-collector.list
   ```

3. Update the package list and install the agent:
   ```bash
   sudo apt update
   sudo apt install kite-collector
   kite-collector install
   ```

Need [osquery](https://osquery.io) on the host too? Install `kite-collector-osquery`
instead — the same agent plus a bundled osqueryd running as the
`kite-osqueryd` systemd service (extensions socket at
`/run/kite-osquery/kite-osquery.em`, which the collector's osquery discovery
source picks up automatically). It is namespaced under `/opt/kite-collector`
so it never conflicts with a standalone osquery package, and installing
either of `kite-collector`/`kite-collector-osquery` cleanly replaces the
other.

### Snap (Universal Linux)

For any Linux distribution that supports Snap (including Ubuntu, Debian, Fedora, Arch Linux, etc.), you can install the agent directly from the Snap Store:

```bash
sudo snap install kite-collector
sudo kite-collector install
sudo kite-collector enroll
sudo snap start --enable kite-collector.kite-collector-daemon
```

For the Snap edition, `install` prepares persistent storage under
`/var/snap/kite-collector/common/certs`; the parent `common` directory remains
owned by snapd, while the collector can secure the `certs` subdirectory. snapd
already manages the binary, service, and updates. Check its state with
`snap services kite-collector` and follow logs with
`sudo snap logs -f kite-collector.kite-collector-daemon`.

### Other Linux Distributions (Fedora, Red Hat, Arch Linux, etc.)

For distributions that do not use the `apt` package manager (such as Fedora, Red Hat Enterprise Linux, CentOS, or Arch Linux):

- **Fedora / Red Hat / CentOS**: Download the `.rpm` package directly from the [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) page and install it using your package manager (e.g., `sudo dnf install ./kite-collector-*.rpm`).
- **Arch Linux / Others**: Download the precompiled binary inside the `.tar.gz` archive from the releases page, extract it, and place it in your `PATH`. Alternatively, you can build from source.

### macOS (Homebrew)

Install `kite-collector` on macOS from our Homebrew tap. The cask clears the Gatekeeper quarantine attribute automatically, so the binary runs without the "unidentified developer" prompt:

```bash
brew install --cask vulnertrack/tap/kite-collector
sudo kite-collector install   # registers launchd against the brew-managed binary — no second copy
```

`brew upgrade --cask kite-collector` is then all it takes: the running
service notices the new binary and restarts onto it. Before
`brew uninstall`, run `sudo kite-collector uninstall` to remove the service
registration (the cask also unloads the launchd job as a safety net).

### Mass deployment from the dashboard

The local kite-collector dashboard includes **Mass deployment**. It generates a
single short-lived Ansible package for Windows, Linux, and macOS targets:

1. Open the dashboard and select **Mass deployment**.
2. Press **Discover computers**. One click combines TCP scanning, SSH banners,
   Bonjour/mDNS, NetBIOS, SSDP, and WS-Discovery. Kite shows the detected local
   IP and queries only its local `/24` after explicit confirmation.
3. Select the compatible computers already discovered in **Machines**. Kite
   derives their operating system and architecture automatically. Additional
   hosts or IP addresses can still be entered as `hostname,os,arch`.
4. Press **Generate deployment package**. Kite automatically requests one
   single-use, two-hour PKI credential per computer and downloads the ZIP. The
   operator never copies or types enrollment credentials.
5. Move the ZIP to a Linux control computer that can reach the targets, unzip
   it, and run `./deploy.sh`.

#### Prepare Windows computers without copying files

The same command can be run on any number of Windows 7/8/10/11 and Windows
Server 2008 R2 or newer computers. On each one, open **Command Prompt (CMD) as
Administrator** and paste:

```cmd
sc.exe config WinRM start= auto & sc.exe start WinRM & winrm quickconfig -quiet & netsh advfirewall firewall add rule name="Kite WinRM HTTP 5985" dir=in action=allow protocol=TCP localport=5985 profile=any remoteip=localsubnet & netstat -ano | findstr ":5985"
```

This command only enables the WinRM management channel; it does not install or
enroll Kite and contains no token, credential, or computer-specific value. The
firewall rule accepts connections only from the local subnet. A line containing
`:5985` should appear when it succeeds. After running it on the
selected computers, generate one ZIP and run `./deploy.sh` once from Linux. The
deployment installs and enrolls every computer using its unique token from the
ZIP. For each Windows target, `deploy.sh` automatically suggests
`COMPUTER-NAME\Administrator`; press Enter to accept it or type another
administrative account. This remains dynamic for packages containing tens or
hundreds of computers.

The script prompts for AD/WinRM and SSH credentials at runtime; infrastructure
passwords are not written to the package. Windows targets require WinRM, while
Linux and macOS targets require SSH and privilege escalation. The enrollment
credentials are confidential and are contained in the generated ZIP, so delete
the ZIP after deployment or when they expire.
The collector release, PKI endpoint, and unique per-computer agent codes are
supplied automatically by the controller and are not operator inputs.

Operating-system detection uses high-confidence evidence such as WinRM or an
SSH banner that identifies the distribution. If the network or firewall offers
no conclusive signal, Kite leaves the OS unselected rather than risk deploying
to a router, printer, or another non-computer device.
When a host advertises OpenSSH but cannot be distinguished as Linux or macOS,
the package performs that check automatically after connecting, detects
`amd64`/`arm64`, and saves the result in `detected-platforms.csv`. The operator
does not type those commands.

### Windows

For Windows, you can install `kite-collector` using any of these simple and fast methods:

#### 1. One-click MSI Installer (Recommended)
Download the latest `kite-collector_<version>_amd64.msi` package from the [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) page. Double-click it to run the installation wizard, or perform a silent enterprise deployment (GPO/Intune) as an administrator:
```powershell
msiexec /i kite-collector_amd64.msi /quiet
```

Need [osquery](https://osquery.io) on the endpoint too? Grab
`kite-collector-osquery_<version>_amd64.msi` instead — the same install plus
a bundled osqueryd registered as the `kite-osqueryd` service, namespaced so
it never conflicts with a standalone osquery install. Details in
[docs/window_install.md](docs/window_install.md#bundled-osquery-msi-kite-collector-osquery).

For a version-pinned, rolling deployment to hundreds of domain-joined Windows
computers, use the included [Ansible fleet deployment](deploy/ansible/README.md).

#### 2. Standalone GUI Wizard
Download the Windows binary `kite-collector_windows_amd64.exe` and double-click it from File Explorer. The binary will automatically detect the double-click launch and open the built-in graphical installation wizard.

#### 3. PowerShell One-Liner
Open a PowerShell console and run the automated installation script directly:
```powershell
irm https://get.kite-collector.dev/install.ps1 | iex
```

#### 4. Windows Package Manager (WinGet)
Install it using the native package manager in Windows 10 & 11:
```powershell
winget install VulnerTrack.KiteCollector
```

#### 5. Scoop
If you use Scoop, add our bucket and install it with:
```powershell
scoop bucket add vulnertrack https://github.com/VulnerTrack/homebrew-tap
scoop install kite-collector
```

### Manual Download

If you prefer to download the precompiled binaries directly:

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64.tar.gz | tar xz

# macOS
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_darwin_arm64.tar.gz | tar xz

# Windows (PowerShell)
irm https://get.kite-collector.dev/install.ps1 | iex

# Windows fast binary-only install
& ([scriptblock]::Create((irm https://get.kite-collector.dev/install.ps1))) -NoService
```

### Build from Source

```bash
make build
```

#### Cross-compile for Windows

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o bin/kite-collector.exe ./cmd/kite-collector
```

## Usage

```bash
# Scan local host (works immediately, no config needed)
./kite-collector scan

# Scan a subnet
./kite-collector scan --scope 192.168.1.0/24

# Include Docker containers
./kite-collector scan --source docker

# JSON output
./kite-collector scan --output json

# Compare two scans to detect drift
./kite-collector diff scan1.db scan2.db

# Continuous monitoring
./kite-collector agent --stream --interval 6h
```

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

## What it discovers

Configuration checks capture the as-built state of every host:

| Check              | What it records                                            |
| ------------------ | ---------------------------------------------------------- |
| SSH config         | `PermitRootLogin`, `PasswordAuthentication`, ciphers, MACs |
| Firewall           | iptables / nftables / ufw rule tables                      |
| Kernel             | ASLR setting, kernel command line, loaded modules          |
| File permissions   | `/etc/shadow`, `/etc/sudoers`, world-readable secrets      |
| Listening services | Open TCP/UDP ports per process                             |
| Database listeners | Postgres / MySQL / MongoDB bind addresses                  |

These observations land in the CMDB as inventory data — kite-collector reports the configuration state; it does not score it against a vulnerability taxonomy.

## Software inventory

Automatically detects and queries installed package managers:

| Package Manager | Platforms                  |
| --------------- | -------------------------- |
| dpkg            | Debian, Ubuntu, Kali       |
| pacman          | Arch, Manjaro, EndeavourOS |
| rpm             | RHEL, Fedora, CentOS, SUSE |

Each package gets a [CPE 2.3](https://nvd.nist.gov/products/cpe) identifier so downstream tools (your SIEM, CMDB, vulnerability scanner) can correlate the inventory against their own data.

## Configuration

Works out of the box with sane defaults and no config file. For customization, create a YAML config:

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

## Output formats

| Format           | Use case                                         |
| ---------------- | ------------------------------------------------ |
| `--output table` | Terminal viewing (default)                       |
| `--output json`  | SIEM ingestion, CI/CD pipelines, API consumption |
| `--output csv`   | Spreadsheets, reporting                          |

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
| `version`        | Print version, commit, build date                               |

The golden path is two commands: `install`, then `status`. When something
looks wrong, `doctor` says why and what to run next.

Deprecated (still work, hidden from help, removal planned): `stream`,
`check-otlp`, `endpoints`, `trust`, `error`, `report`, `query`, `db`,
`diff`, `discover-services`, `web-fingerprint`, `storage-fingerprint`.
Each prints a pointer to its replacement when invoked.

## Asset classification

Every discovered asset is classified on two axes:

**Authorization** (is this asset supposed to be here?):

- `unknown` -- default, not yet evaluated
- `authorized` -- matches an entry in the allowlist
- `unauthorized` -- explicitly not in the allowlist

**Managed state** (does this asset meet our security controls?):

- `unknown` -- default, controls not configured
- `managed` -- all required controls present
- `unmanaged` -- missing one or more required controls

Assets never default to `authorized`. Only positive matches against your source of truth produce `authorized`.

## Database

All results are stored in a portable SQLite file at `./kite.db`:

```bash
# Query assets
sqlite3 kite.db "SELECT hostname, asset_type, is_authorized FROM assets"

# Query installed software
sqlite3 kite.db "SELECT software_name, version, cpe23 FROM installed_software LIMIT 10"

# Query config findings
sqlite3 kite.db "SELECT check_id, severity, title FROM config_findings"

# Scan history
sqlite3 kite.db "SELECT started_at, status, total_assets FROM scan_runs ORDER BY started_at DESC"
```

## Platform integration

kite-collector can feed into the [Vulnertrack Intelligence Engine](https://github.com/VulnerTrack/vulnertrack-intelligence-engine) so its inventory becomes the source-of-truth for downstream tools:

```bash
# Import scan results into ClickHouse
vie kite scan --scope 192.168.1.0/24 --import

# Query imported assets
vie kite assets --authorized unauthorized
```

## Scan via API

When the agent runs in long-lived mode (`agent --stream` or `agent` with the
REST server enabled), scans can be triggered, watched, and cancelled over HTTP
instead of SSH-ing to the host to run `kite-collector scan`. The dashboard uses
the same endpoints.

All routes sit behind the `MTLSOrAPIKey` middleware (RFC-0063): when an API
key is configured every request must present it via `X-API-Key` or a valid
mTLS client certificate.

Only one scan runs at a time. A second `POST /api/v1/scans` while a scan is
already running returns `409 Conflict` with the active scan's id, so callers
can poll it instead of retrying blindly.

### Trigger a scan

```bash
# Minimal trigger — uses the operator-declared config as-is.
curl -sS -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: $KITE_API_KEY"

# 202 Accepted
# Location: /api/v1/scans/019515a1-7f42-7f0a-8a1c-...
# {"scan_run_id":"019515a1-7f42-7f0a-8a1c-..."}
```

Narrow the run to a subset of declared sources (sources must already be
enabled in the config — the endpoint cannot widen scope):

```bash
curl -sS -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: $KITE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sources": ["network", "docker"]}'
```

mTLS variant (no API key; client cert authenticates the caller):

```bash
curl -sS -X POST https://kite.internal:8443/api/v1/scans \
  --cert /etc/kite/tls/client.crt \
  --key  /etc/kite/tls/client.key  \
  --cacert /etc/kite/tls/ca.crt
```

### Inspect and follow a scan

```bash
# Snapshot of a specific run.
curl -sS http://localhost:8080/api/v1/scans/$ID -H "X-API-Key: $KITE_API_KEY"

# Live progress via Server-Sent Events. --no-buffer disables curl's line
# buffering so status/progress/done frames land as soon as the agent emits
# them; the stream closes on terminal status.
curl -sS --no-buffer http://localhost:8080/api/v1/scans/$ID/events \
  -H "X-API-Key: $KITE_API_KEY"

# event: snapshot
# data: {"id":"...","status":"running", ...}
#
# event: progress
# data: {"scan_run_id":"...","type":"progress", ...}
#
# event: done
# data: {"scan_run_id":"...","type":"done", ...}
```

### Cancel a running scan

```bash
curl -sS -X POST http://localhost:8080/api/v1/scans/$ID/cancel \
  -H "X-API-Key: $KITE_API_KEY"

# 202 Accepted
# {"scan_run_id":"...","cancel_requested_at":"2026-04-21T14:47:36Z"}
```

The scan row is stamped with `cancel_requested_at` and the engine finalises
the run as `timed_out` once it honours the cancellation (typically at the
next source boundary).

### Kill switch

Set `KITE_COLLECTOR_SCAN_API=off` to force the trigger/cancel/SSE endpoints
to return `503 Service Unavailable` and make the dashboard "Run Scan" button
fall back to a read-only badge. Useful as a rollback knob without a redeploy.

### Dashboard autoreload

The dashboard mounts the same coordinator. The status panel polls
`/fragments/scan-status` every three seconds via HTMX, so clicking "Run Scan"
transitions the badge through `running → completed / failed / timed_out`
without a manual reload:

```html
<div
  id="scan-status"
  hx-get="/fragments/scan-status"
  hx-trigger="load, every 3s"
  hx-swap="innerHTML"
></div>
```

## Container observability (dashboard)

The dashboard's **Containers** page is a live view of the local Docker /
Podman / docker-compose environment, inspired by lazydocker and built on the
Engine API directly (no SDK, no external tooling):

- **State at a glance** — every container with an icon status + health,
  grouped by compose project, auto-refreshing every 10 s with pause/resume.
- **Custom metric graphs** — CPU % and Memory % sparklines by default
  (`docker stats`-accurate math), plus a column for **any** numeric field of
  the Engine stats document by dotted stat path
  (`?graph=memory_stats.stats.pgmajfault`). Each container's *Graphs* drawer
  lists every available path with its current value — click *Graph* to add
  it. Customised views live in the URL, so bookmark them.
- **Image ancestor layers** — `docker history` for any image, from the image
  inventory or a container's image link.

A JSON snapshot mirrors the page for scripted monitoring:
`GET /api/v1/containers/snapshot.json`. Full details, engine resolution
order, and the collection model: [docs/container-observability.md](docs/container-observability.md).

## Streaming to OpenTelemetry

kite-collector pushes asset lifecycle events to any OTLP-compatible collector (Grafana Alloy, OpenTelemetry Collector, Datadog Agent, etc.) as **OTLP log records over HTTP/JSON**.

### Quick start

1. Add the streaming block to your config file:

```yaml
streaming:
  interval: 6h
  otlp:
    endpoint: http://localhost:4318
    protocol: http
```

2. Run in continuous mode:

```bash
./kite-collector agent --stream --interval 6h
```

Events are sent to `<endpoint>/v1/logs` as they are generated each scan cycle.

### Environment variable override

You can skip the config file entirely using `KITE_` prefixed env vars:

```bash
export KITE_STREAMING_OTLP_ENDPOINT=otelcol:4318
export KITE_STREAMING_OTLP_PROTOCOL=http
./kite-collector agent --stream
```

### Mutual TLS

For production deployments with mTLS:

```yaml
streaming:
  otlp:
    endpoint: https://otelcol.internal:4318
    protocol: http
    tls:
      enabled: true
      cert_file: /etc/kite/tls/client.crt
      key_file: /etc/kite/tls/client.key
      ca_file: /etc/kite/tls/ca.crt
```

### Event schema

Each event is an OTLP log record with these attributes:

| Attribute         | Description                                                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `service.name`    | Always `kite-collector` (resource attribute)                                                                                     |
| `service.version` | Build version (resource attribute)                                                                                               |
| `event_type`      | One of: `AssetDiscovered`, `AssetUpdated`, `UnauthorizedAssetDetected`, `UnmanagedAssetDetected`, `AssetNotSeen`, `AssetRemoved` |
| `asset_id`        | UUID of the affected asset                                                                                                       |
| `scan_run_id`     | UUID of the scan run that produced the event                                                                                     |
| `severity`        | `low`, `medium`, `high`, or `critical`                                                                                           |

Severity maps to OTLP severity numbers: low=5 (DEBUG), medium=9 (INFO), high=13 (WARN), critical=17 (ERROR).

### Example: OpenTelemetry Collector config

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  loki:
    endpoint: http://loki:3100/loki/api/v1/push
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [loki, debug]
```

### Example: Docker Compose with collector

```yaml
services:
  kite-collector:
    build: .
    command: ["agent", "--stream", "--config", "/etc/kite/config.yaml"]
    environment:
      KITE_STREAMING_OTLP_ENDPOINT: "otelcol:4318"
      KITE_STREAMING_OTLP_PROTOCOL: "http"
    depends_on: [otelcol]

  otelcol:
    image: otel/opentelemetry-collector-contrib:latest
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol/config.yaml:ro
    command: ["--config", "/etc/otelcol/config.yaml"]
    ports:
      - "4318:4318"
```

### Retry behavior

The emitter retries transient failures (5xx, 429, connection errors) with exponential backoff -- 3 attempts, starting at 1s, capped at 30s. Client errors (4xx) are not retried.

### Verify the pipeline

```bash
make test-otlp
```

This starts a collector, runs a streaming scan, and verifies events arrive at the collector.

### Runnable sample

See [`samples/streaming-to-otel/`](samples/streaming-to-otel/) for a self-contained example: `docker compose up` starts a collector, then you point kite-collector at it.

## Security

- **Read-only** -- never writes to, modifies, or executes code on discovered systems
- **No credentials in storage** -- SQLite contains asset data only, never tokens or passwords
- **Structured logging** -- `log/slog` JSON output with automatic credential redaction
- **Minimal privileges** -- works as non-root with graceful degradation for permission-denied paths

## License

MIT, see [LICENSE](LICENSE).

## Windows 7 legacy inventory

Mass deployment automatically selects the isolated Windows/386 collector for
Windows 7 and 32-bit computers. It stores its transactional inventory database
at `C:\ProgramData\kite-collector\kite.db` and exposes a loopback-only local
dashboard at `http://127.0.0.1:9090`. The service scans at startup and every six
hours, covering core OS, hardware, software, updates, identity, services,
processes, networking, storage, drivers, scheduled tasks, startup entries, and
Windows 7 security state. Completed snapshots sync over mTLS OTLP: asset
summaries reach `analytics_asset_current_state` and full category JSON reaches
`analytics_windows_inventory_categories` in Supabase, with retry every five
minutes after transient failures. See `legacy/windows7/README.md` for its deliberately
isolated compatibility architecture and CLI commands.
