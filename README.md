# kite-collector

Configuration Management Database (CMDB) agent for IT asset discovery.

A single binary that scans your network, inventories installed software, and captures the as-built configuration state of every host it observes. Discovery sources span cloud APIs, hypervisors, OS, network listeners, and dozens of config files (SSH, firewall, PAM, nsswitch, MongoDB, MySQL, …).

Results are stored in a local SQLite database. No servers, no dependencies, fully offline.

## Install

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

### Snap (Universal Linux)

For any Linux distribution that supports Snap (including Ubuntu, Debian, Fedora, Arch Linux, etc.), you can install the agent directly from the Snap Store:

```bash
sudo snap install kite-collector
```

### Other Linux Distributions (Fedora, Red Hat, Arch Linux, etc.)

For distributions that do not use the `apt` package manager (such as Fedora, Red Hat Enterprise Linux, CentOS, or Arch Linux):

- **Fedora / Red Hat / CentOS**: Download the `.rpm` package directly from the [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) page and install it using your package manager (e.g., `sudo dnf install ./kite-collector-*.rpm`).
- **Arch Linux / Others**: Download the precompiled binary inside the `.tar.gz` archive from the releases page, extract it, and place it in your `PATH`. Alternatively, you can build from source.

### Windows

For Windows, you can install `kite-collector` using any of these simple and fast methods:

#### 1. One-click MSI Installer (Recommended)
Download the latest `kite-collector_<version>_amd64.msi` package from the [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases) page. Double-click it to run the installation wizard, or perform a silent enterprise deployment (GPO/Intune) as an administrator:
```powershell
msiexec /i kite-collector_amd64.msi /quiet
```

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
    allowlist_file: ./configs/authorized-assets.yaml
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

| Command            | Description                                |
| ------------------ | ------------------------------------------ |
| `scan`             | One-shot discovery + configuration audit   |
| `agent --stream`   | Continuous mode with configurable interval |
| `diff <db1> <db2>` | Compare two scan databases                 |
| `report`           | Generate asset report                      |
| `version`          | Print version, commit, build date          |

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
