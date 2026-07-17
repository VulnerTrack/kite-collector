# Container discovery smoke test

A docker-compose harness that verifies the per-host container collector
(`internal/discovery/agent/containers`) both **connects** to a real Docker
daemon and extracts **correct, audit-grade data** from real containers.

## Run it

```bash
make test-smoke-containers
# or directly:
./tests/e2e/containers/run.sh
```

Requires `docker` and the `docker compose` plugin. `run.sh` starts the fixture
containers, runs the collector inside a Go test that mounts the same Docker
socket (read-only), and exits non-zero if any assertion fails.

## What it checks

`docker-compose.smoke.yml` starts five fixtures, each pinned to a known,
deterministic property, identified by the `com.vulnertrack.role` label (never
by name — compose adds a project prefix):

| Fixture      | Property exercised                        | Field asserted                     |
|--------------|-------------------------------------------|------------------------------------|
| `web`        | running + published port + RO bind mount  | `Image`, `State`, `Ports`, `Mounts`, `Labels` |
| `privileged` | `--privileged`                            | `Privileged` (CWE-732)             |
| `hostnet`    | `--network=host`                          | `HostNetwork` (CWE-668)            |
| `nonroot`    | `user: 1000:1000`                         | `RootUID`                          |
| `exited`     | exits with code 7                         | `State=exited`, `ExitCode`         |

The test polls the collector until all fixtures are present and settled, so it
is robust to container startup ordering.

## Why this is a Go test and not a `kite-collector scan` shell assertion

**The `containers` collector is not currently wired into the `kite-collector`
binary.** No production code imports `internal/discovery/agent/containers`; the
agent probe (`internal/discovery/agent/probe.go`) collects interfaces,
software, and drivers but never calls `containers.NewChainCollector()`, and
nothing writes the `host_containers` table. So `kite-collector scan` emits no
container data — a black-box CLI smoke test would assert nothing.

This harness therefore drives the collector package directly (the only way to
observe container discovery today). It doubles as the regression gate to have
in place **before** wiring the collector into the agent probe / streaming path.
Once that wiring lands, an end-to-end variant can additionally assert the data
surfaces through `kite-collector scan --output json` / the `host_containers`
table.

The same gap applies to the sibling chains `vpn`, `firewall`, `vms`,
`certificates`, `cloudcreds`, `browserext`, `editorext`, and `scheduled`.
