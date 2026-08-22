# kite container + settings smoke test

An **end-to-end** smoke test that drives the real `kite-collector` binary
(black-box — not the Go packages directly) to verify two things:

- **Containers** — the `docker` discovery source, enabled via a settings file,
  discovers fixture containers and extracts their fields (image, published port,
  `privileged` flag, compose-project label) into asset tags.
- **Settings** — a valid settings file is accepted and drives discovery; the
  `host` setting is honored (a wrong socket yields zero containers — no silent
  auto-detect); an invalid settings file is rejected before scanning.

## Run it

```bash
make test-kite-containers
# or directly:
./tests/e2e/kite-containers/run.sh
```

Requires `docker` + the `docker compose` plugin. `run.sh` starts the fixtures,
builds the kite-collector binary into a runner image, runs `smoke.sh` against
the mounted Docker socket, and exits non-zero if any check fails.

## What it checks

`smoke.sh` runs `kite-collector scan --config <settings> --output json` and
asserts on the JSON asset array:

| Check | Verifies |
|-------|----------|
| valid `settings.yaml` accepted | settings load + `config.Validate()` pass |
| `--output json` is a JSON array | the scan JSON contract |
| containers discovered (`machine_type=container`, `discovery_source=docker`) | the wired docker source runs end-to-end |
| web fixture image `nginx` | image extraction |
| published port `18081` in tags | port mapping extraction |
| `tags.privileged=true` | privileged detection (CWE-732 signal) |
| `tags.compose_project` | Docker label capture |
| wrong-host settings → 0 containers | the `host` **setting is honored** (no auto-detect fallback) |
| invalid settings → non-zero exit | settings are **validated** before scanning |

## Daily workspace

`.github/workflows/kite-containers-smoke.yml` runs this every day (and on
changes to the docker source / config / this test), uploading the log. It
surfaces drift in the Docker Engine API, the asset-JSON contract, or config
validation early.

## Notes / findings

- This exercises `internal/discovery/docker` (the Tier-1 `dockerdisc` source),
  which **is** wired into `kite-collector scan`. That is distinct from
  `internal/discovery/agent/containers` (Tier-2, per-host), which is **not** yet
  wired into the CLI — that one is covered by `tests/e2e/containers` at the
  package level.
- The docker source does **not** honor `enabled: false` — it runs (and
  auto-detects a socket) whenever registered, so the settings lever this test
  asserts is `host`, not `enabled`. Worth wiring an `enabled` gate into the
  docker source if operators are expected to be able to turn it off via config.
- The `--source` CLI flag on `scan` is currently **not applied** — sources are
  controlled by the config file. That's why this test drives everything through
  settings.
