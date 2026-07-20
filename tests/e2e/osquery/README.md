# Simulated osquery environment

A docker-compose stack that stands up a **real osqueryd** exposing its Thrift
extensions socket — a faithful, reproducible stand-in for an osquery-equipped
host. Use it to develop and test a future osquery-backed kite collector without
installing osquery locally (or fighting the `nettle3` conflict on Arch).

## Run it

```bash
cd tests/e2e/osquery

# One-shot: bring up osqueryd, wait until healthy, run the probe, print results.
docker compose -f docker-compose.osquery.yml run --rm --build probe

# Or keep it running as a long-lived environment:
docker compose -f docker-compose.osquery.yml up --build          # Ctrl-C to stop
docker compose -f docker-compose.osquery.yml down -v             # tear down
```

`make sim-osquery` runs the one-shot probe.

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
| table exists (×16) | a table a collector would consume was removed/renamed |
| columns (×6) | a column a collector reads was removed/renamed |

It runs against a **matrix** of two targets so drift surfaces early:

- **pinned** (`5.15.0`) — the version a kite osquery-backed collector would target.
- **latest** — whatever the osquery repo currently publishes.

When `latest` fails but `pinned` passes, a new osquery release broke something —
and you know before adopting it. `fail-fast: false` keeps both legs reporting;
each run uploads its `checks-<label>.log` as an artifact.

Run the battery locally:

```bash
make osquery-checks                       # pinned 5.15.0
OSQUERY_VERSION=latest make osquery-checks # test drift against latest
```

## What it is

| Service   | Role |
|-----------|------|
| `osquery` | `osqueryd --ephemeral` in the foreground, extensions socket at `/var/osquery/osquery.em` on the `osq-socket` volume. Healthy only when it answers a query over that socket. |
| `probe`   | Attaches with `osqueryi --connect` and runs `osquery_info` / `processes` / `os_version`, asserting a non-empty version comes back. Green = daemon + socket work. |

The probe uses `--connect` (attach to the running daemon) rather than a
standalone `osqueryi` shell, so it exercises the **socket**, which is the
integration surface — not just the osquery binary.

## How kite would consume it

osquery's client protocol is Thrift over a **unix domain socket** (there is no
native TCP). A Go client (`github.com/osquery/osquery-go`) binds to that socket.
To wire a kite runner into this stack, mount the same volume read-only and point
the collector at the socket:

```yaml
  kite-runner:
    image: golang:1.26-bookworm
    depends_on:
      osquery:
        condition: service_healthy
    volumes:
      - osq-socket:/var/osquery:ro
    environment:
      KITE_OSQUERY_SOCKET: "/var/osquery/osquery.em"
    command: ["go", "test", "-tags", "osquerysim", "./..."]
```

> **Status:** kite has no osquery client today — the container collector
> (`internal/discovery/agent/containers`) talks to the Docker Engine API, not
> osquery. This environment is groundwork for an osquery-backed collector; it is
> not yet consumed by the binary.

## Notes

- **Host visibility:** osqueryd sees the container's own `/proc`. To simulate a
  host's full process/socket inventory, add `pid: host` (and mount `/proc`) to
  the `osquery` service — off by default to keep the sim isolated and unprivileged.
- **Version pinning:** `Dockerfile.osquery` pins `OSQUERY_VERSION` for
  reproducibility. Bump the ARG to move it.
- **Platform:** the apt repo line is `arch=amd64`. On arm64 hosts, switch to
  osquery's arm64 channel.
