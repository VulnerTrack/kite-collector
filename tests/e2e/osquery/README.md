# Simulated osquery environment

A docker-compose stack that stands up a **real osqueryd** with events enabled —
inotify FIM, event-driven YARA scanning, and canary rules baked in — exposing
its Thrift extensions socket. A faithful, reproducible stand-in for an
osquery-equipped host, used both to test the kite osquery discovery source
(`internal/discovery/osquery`) and to catch upstream osquery drift daily.

## Run it

```bash
cd tests/e2e/osquery

# One-shot: bring up osqueryd, wait until healthy, run the probe, print results.
docker compose -f docker-compose.osquery.yml run --rm --build probe

# Or keep it running as a long-lived environment:
docker compose -f docker-compose.osquery.yml up --build          # Ctrl-C to stop
docker compose -f docker-compose.osquery.yml down -v             # tear down
```

Make targets (each tears the stack down afterwards):

| Target | What it runs |
|--------|--------------|
| `make sim-osquery` | the one-shot probe (liveness + YARA demo) |
| `make osquery-checks` | the 48-check drift battery (`checks.sh`) |
| `make osquery-edge` | the 20-check edge-case / error-state battery (`edge.sh`) |
| `make test-osquery-kite` | the collector's osquery source (`go test -tags osquerysim`) against the live daemon |

Override the daemon version on any of them: `OSQUERY_VERSION=latest make osquery-checks`.

## Daily drift check — "what could go wrong"

`.github/workflows/osquery-smoke.yml` runs this environment **every day** and,
instead of a single green/red, executes a diagnostic battery (`checks.sh`) that
names *which* failure mode hit:

| Check | Breaks when |
|-------|-------------|
| binary + version | the apt repo, GPG key, or package name changed |
| extensions socket present | osqueryd failed to start or moved the socket |
| `--connect` over socket | the client attach behavior changed (it has before) |
| `osquery_info` queryable | the daemon answers but returns garbage |
| table exists (×22) | a table a collector consumes was removed/renamed |
| columns (×11) | a column a collector reads was removed/renamed |
| events subsystem (×3) | the inotify publisher or a subscriber went inactive |
| YARA on-demand (+ negative) | rules stopped compiling or started matching everything |
| YARA count = distinct rules | `yara.count` changed meaning (e.g. to string-hits), which would silently reskew `yara_match_count` |
| hash vs sha256sum | the hash table disagrees with coreutils |
| FIM delivery | file_events stopped seeing writes under `file_paths` |
| YARA events | yara_events stopped scanning on change |
| collision pin | the inotify watch-ownership collision (below) changed upstream |

The **edge battery** (`edge.sh`, also in the daily run) pins how osquery
*fails*: loud errors (bad SQL, missing tables, constraint-required tables,
dead socket) versus the **silent zero-row traps** — a missing or
*uncompilable* YARA sigfile and a missing scan target all return rc=0 with
zero rows, indistinguishable from a clean scan. Collector error handling is
designed against these pinned behaviors, not assumptions.

The **kite leg** runs the collector's own discovery source against the live
daemon (see below), so on `latest` it catches an osquery release breaking the
kite client before adoption.

Everything runs against a **matrix** of two targets so drift surfaces early:

- **pinned** (`5.15.0`) — the version the kite osquery source targets.
- **latest** — whatever the osquery repo currently publishes.

When `latest` fails but `pinned` passes, a new osquery release broke something —
and you know before adopting it. `fail-fast: false` keeps both legs reporting;
each run uploads its `checks/edge/kite-<label>.log` files as artifacts.

## The inotify watch-ownership collision (do not watch the same paths twice)

osquery's inotify publisher hands each kernel watch descriptor to exactly
**one** subscriber (`shouldFire`: `sc.get() != ec->isub_ctx.get()`), and
`inotify_add_watch` dedups by path. When `file_events` and `yara_events` watch
the same directory, whichever registers last (yara_events) **silently steals
the watch** and file_events goes deaf on that subtree — zero errors anywhere.

This sim therefore watches disjoint subtrees (`/var/kite/watch/fim` for FIM,
`/var/kite/watch/yara` for event-driven YARA), and `checks.sh` pins the
collision itself so an upstream fix shows up as a named check flip rather than
silent behavior drift. A production `file_paths` config must keep FIM and
YARA-event categories disjoint for the same reason.

## What it is

| Service   | Role |
|-----------|------|
| `osquery` | `osqueryd --ephemeral` in the foreground, events ON, extensions socket at `/var/osquery/osquery.em` on the `osq-socket` volume, canary YARA rules at `/etc/osquery/yara/kite.yar`, FIM+YARA watches over the shared `osq-watch` volume. |
| `probe`   | Attaches with `osqueryi --connect`, runs identity queries plus an on-demand YARA canary scan. Green = daemon + socket work. |
| `checks`  | The 48-check drift battery. |
| `edge`    | The 20-check edge-case / error-state battery. |
| `kite-runner` | `golang` image running `go test -tags osquerysim ./tests/e2e/osquery/...` — the collector's real discovery source against the live daemon over the shared socket volume. |

The probe uses `--connect` (attach to the running daemon) rather than a
standalone `osqueryi` shell, so it exercises the **socket**, which is the
integration surface — not just the osquery binary.

## How kite consumes it

`internal/discovery/osquery` is a discovery source registered in the binary.
It speaks a minimal hand-rolled Thrift binary-protocol client (`query` +
`ping` only — no vendor SDK, mirroring the docker source) to the extensions
socket, reading host identity (`osquery_info`, `system_info`, `os_version`,
`kernel_info`), optional on-demand YARA scans (`yara_sigfile` + `yara_paths`
config), and FIM `file_events`.

Socket resolution: `sources.osquery.socket` config → `KITE_OSQUERY_SOCKET`
env → platform defaults (`/var/osquery/osquery.em` on Linux/macOS, the pipes
below on Windows). Hosts without osqueryd log one per-scan warning and
contribute nothing.

Design decisions verified by this sim:

- **Silent-zero guard**: the source only reports a YARA scan when the sigfile
  is *proven* visible to the daemon (`file` table probe), because osquery
  answers a missing/uncompilable sigfile with rc=0 and zero rows.
- **Loud errors** decode as `queryError` (distinct from transport failures,
  which feed the circuit breaker).
- **FIM is eventually consistent**: consumers poll `file_events` with a
  budget; single-shot reads are wrong by design.
- **FIM is platform-split**: `file_events` is POSIX-only in osquery's specs;
  a Windows daemon serves `ntfs_journal_events` (no sha256, `path` instead of
  `target_path`). The source falls back automatically on an unknown-table
  rejection.

### The deployment surface already exists (Windows MSI + Debian deb)

Two release artifacts ship osqueryd 5.15.0 bundled with the collector, both
pinned to the same version this sim tracks:

- **Windows**: `kite-collector-osquery_<v>_amd64.msi`
  (`scripts/build-msi.sh --with-osquery`, `cmd/kite-collector/wix.wxs`
  with `-D OSQUERY`) — service `kite-osqueryd`, details below.
- **Debian**: `kite-collector-osquery_<v>_amd64.deb`
  (`scripts/build-deb-osquery.sh`, `packaging/deb/nfpm-osquery.yaml`) —
  systemd unit `kite-osqueryd.service`, daemon under
  `/opt/kite-collector/osquery`, extensions socket at
  `/run/kite-osquery/kite-osquery.em` (first entry in
  `internal/discovery/osquery/socket_unix.go` defaults) and a
  `kite-collector.service.d` drop-in exporting `KITE_OSQUERY_SOCKET`.
  `make test-deb-osquery` runs its container install/run battery.
On Windows the Thrift endpoint is a **named pipe**, not a unix socket, and
the MSI fixes the contract the client honors:

- pipe: `\\.\pipe\kite-osquery.em` (namespaced; standalone osquery uses
  `\\.\pipe\osquery.em`) — both are default lookup paths in
  `internal/discovery/osquery/socket_windows.go`, dialed via `go-winio`.
- env: `KITE_OSQUERY_SOCKET` is set machine-wide to that pipe name at install
  time, so the client-side lookup is identical on both platforms: read
  `KITE_OSQUERY_SOCKET`, dial it untouched.

Changing either value is a breaking change for already-deployed bundles.

## Notes

- **Host visibility:** osqueryd sees the container's own `/proc`. To simulate a
  host's full process/socket inventory, add `pid: host` (and mount `/proc`) to
  the `osquery` service — off by default to keep the sim isolated and unprivileged.
- **Version pinning:** `Dockerfile.osquery` pins `OSQUERY_VERSION` for
  reproducibility. Bump the ARG to move it.
- **Watch dirs must pre-exist:** the daemon resolves `file_paths` globs to
  inotify watches at startup; `fim/` and `yara/` are created in the image so
  the named volume inherits them before osqueryd boots.
- **Platform:** the apt repo line is `arch=amd64`. On arm64 hosts, switch to
  osquery's arm64 channel.
