# snap-install e2e — `kite-collector install` on a snap-installed machine

Verifies what `kite-collector install` does when the operator installed
kite-collector **via snap** (`snap install kite-collector`, published by
goreleaser with `confinement: strict`, see `.goreleaser.yaml`) and then runs
the install subcommand from the snap-provided binary.

## The two containers

| container     | role |
|---------------|------|
| `ubuntu`      | The machine under test. Ubuntu 24.04 with **systemd as PID 1** (privileged) and the real kite-collector binary staged exactly as snapd leaves it: `/snap/kite-collector/x1/` (read-only tree, `chmod -R a-w`), a `current` symlink, `/var/snap/kite-collector/{x1,common}` data dirs, and a `/snap/bin/kite-collector` run shim that exports the full `SNAP*` environment. `scenario.sh` runs the install scenarios and writes evidence to the shared `/results` volume. |
| `test-runner` | Reads `/results` and asserts (`checks.sh`). Its exit code is the test verdict. Kept separate so verdicts can't depend on — or disturb — the machine's state. |

## What it asserts

- `install --dry-run` from the snap path exits 0, plans the copy
  `/snap/kite-collector/x1/kite-collector → /usr/local/bin/kite-collector`,
  and writes nothing.
- Real `install` exits 0 and **relocates the binary out of the snap tree**
  (sha256 of `/usr/local/bin/kite-collector` matches the snap binary) — the
  registered service must survive `snap refresh` / `snap remove`.
- The systemd unit exists, is `enabled`, and its `ExecStart` references the
  installed binary — never a `/snap/...` path.
- Unenrolled agent: the service is registered but **not started** (no certs →
  starting would only produce auth-error noise), and the post-install report
  tells the operator to enroll.
- Nothing under `/snap` was created or modified (the real squashfs is
  read-only; any write attempt is a bug).
- Re-running `install` (what a snap refresh hook would do) exits 0.

## What is simulated vs. real

Real: the compiled binary, the snap filesystem layout, the `SNAP*`
environment, systemd as the service manager, the read-only snap tree
(via `a-w` permissions).

Not emulated: **snapd itself and strict confinement** (AppArmor/seccomp).
snapd does not run inside docker. Under real `confinement: strict`, the
sandbox would deny writing `/usr/local/bin` and talking to systemd — so this
suite verifies the install logic's behavior given the snap environment, not
the sandbox. If `install` is expected to work for snap users on real hosts,
the snap needs classic confinement (or interfaces + a snapcraft `daemon:`),
which is a packaging decision outside this test.

## Run

```sh
./run.sh
```

Requires docker + the compose plugin; the `ubuntu` container is privileged
(systemd PID 1). On failure, evidence files live in the `results` volume:
`docker compose -f docker-compose.snap.yml -p kite-snap-install-e2e \
  run --rm --entrypoint cat test-runner /results/install.out`
