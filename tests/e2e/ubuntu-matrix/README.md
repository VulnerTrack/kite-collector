# Ubuntu multi-version package-discovery matrix

RFC-0149. Runs the **real compiled `kite-collector` binary**'s `software.Dpkg`
collector inside **real, unmodified Ubuntu images**, and asserts the discovered
`name` / `version` / `architecture` / `cpe23` / `package_manager` against a
known-good fixture per Ubuntu version.

## Why this exists

`internal/discovery/agent/software/dpkg.go` is the sole upstream source for
`kite_installed_software`, and through `cpe_matching_steps.py`'s
`InstalledSoftware.cpe23 → Platform.natural_key → affects_platform →
Vulnerability` join, the sole upstream source for every CVE-exposure number
this platform reports to a client.

Before this suite it was verified only against hand-written Go string
fixtures. A `dpkg-query` output shape the parser mishandles does not crash
anything — it produces a malformed CPE that silently matches **no** CVE. That
is a false negative in a security report, and nothing in either language would
have caught it.

## What each leg does

1. `go build` the collector for `linux/$GOARCH` on the host.
2. Boot the target's pinned image (`ubuntu:22.04@sha256:…`) with
   `testcontainers-go`, keeping it alive with `sleep infinity`.
3. Copy the binary, the leg's seed script and `fixtures/scan.yaml` into it.
4. Run the seed script: `dpkg --add-architecture i386`, install the seed set,
   purge the purge-probe package.
5. Exec `kite-collector scan --config /scan.yaml --output json`, redirecting
   stdout and stderr to files inside the container.
6. Copy both back, parse the discovered software, evaluate parity checks.
7. Write `.matrix-reports/<slug>.json` (the §5.4 ingest payload) and a
   markdown diff to `$GITHUB_STEP_SUMMARY`.

**No Dockerfile, no compose file.** R1 asks for *unmodified* `ubuntu:X`
images, and the supply-chain claim in §6.5 rests on
`ContainerTestFixture.image_digest` being the digest of the artifact that
actually ran. A derived image would put a build step in between, so the pinned
digest would describe a `FROM` line rather than the thing under test. Files are
injected at run time instead.

## Seed set, and why each package is there

| Package | Shape | What it protects |
|---|---|---|
| `vim` | epoch version (`2:9.x`) | CPE normalisation strips `:`, fusing the epoch onto the upstream version. This is the exact line that has sat unreferenced in `internal/discovery/agent/software/testdata/dpkg_input.txt`. |
| `libc6:i386` | architecture-qualified multi-arch | `dpkg-query` then emits two rows named `libc6` differing only in `${Architecture}`; collapsing or suffix-mangling either loses a real package. |
| `hello` | installed, then purged | A removed package must not linger in discovery output as a phantom CVE exposure. |
| `bsdutils` | epoch version, already in the base image | Proves the base image — not just the seeded packages — parses correctly, at zero install cost. |

Seed scripts install only from official Canonical archives
(`archive.ubuntu.com` / `security.ubuntu.com`, with `old-releases.ubuntu.com`
as the documented fallback for the retired 20.04 leg). No internal mirrors, no
credentials.

## Fixture conventions

`fixtures/expected/*.expected.json` asserts **exact values where dpkg output is
deterministic** (name, architecture, package_manager) and **patterns where
Ubuntu security updates move the value** (version). A hardcoded version string
would turn every SRU into a red build.

`known_issues` lists finding types that are acknowledged for a package or for
the whole target. A waived finding is **still produced, still ingested, and
still shown in the PR summary** — as `acknowledged` — it simply does not fail
the leg. Removing the annotation is how a known issue becomes blocking again.

One waiver ships today: `epoch_version_mismatch` on the epoch packages.
`BuildCPE23` normalises `2:9.0.2114-1` to `29.0.2114-1`, which will never match
NVD's `9.0.2114`. Per RFC-0149 §2.2 this RFC is a *verification* RFC — surfacing
that is the deliverable; fixing `cpe.go` is a separate change. The waiver is
narrow: a package that stops carrying an epoch at all still fails, unwaived.

## Finding types

The closed enum from §4.1.4. `high` is reserved for findings that would
plausibly suppress a real CVE match — a security policy, not a triage scale.

| Finding | Severity | Meaning |
|---|---|---|
| `epoch_version_mismatch` | high | The derived CPE mishandles a Debian epoch. |
| `multiarch_suffix_leak` | high | An architecture suffix leaked into the package name. |
| `cpe_generation_mismatch` | high | `cpe23` is empty, structurally malformed, or not what the observed name/version/arch derive to. |
| `package_manager_label_drift` | high | A package is labelled with something other than `dpkg`. |
| `count_mismatch` | medium/high | Too few packages, a missing seeded package, a missing architecture, or a version that failed its declared pattern. |
| `encoding_error` | medium | Invalid UTF-8 / control characters, or more per-line parse errors than budgeted. |
| `purged_package_included` | high | A purged package reappeared as installed. |
| `base_image_digest_drift` | medium/info | The tag no longer resolves to the pinned digest, or the target is unpinned. `info` on the rolling `devel` leg. |

`infra_error` is not a finding. A container pull, boot or exec failure is never
an assertion outcome, and is never aggregated as a pass or as a real parity
failure — conflating "Docker Hub was rate-limited" with "the collector has a
bug" would corrupt the entire signal.

## Running it

```bash
make test-ubuntu-matrix                                # all four legs
KITE_MATRIX_TARGET=ubuntu-22.04 make test-ubuntu-matrix # one leg
make pin-ubuntu-matrix                                 # re-pin image digests
./pin-digests.sh --check                               # drift check, no writes
```

The pure classification logic (`checks.go`, `report.go`, `targets.go`,
`digest.go`) is **not** behind the `e2e` tag, so `go vet`, `golangci-lint` and
plain `make test` all cover it with no Docker daemon. Only `matrix_test.go`
needs containers.

| Variable | Effect |
|---|---|
| `KITE_MATRIX_TARGET` | Run one leg. An unknown slug is fatal — a `-run` regex that matches nothing exits 0, and a matrix that silently runs zero legs while reporting green is worse than no matrix. |
| `KITE_MATRIX_DRIFT_CHECK=1` | Re-resolve each tag against the registry and report drift. Weekly schedule only: a per-PR round trip would add Docker Hub's rate limit to every push. |
| `KITE_MATRIX_REPORT_DIR` | Where `<slug>.json` artifacts land. Default `.matrix-reports/`. |
| `CI` | When set, an `infra_error` fails the job instead of skipping. |

## Digest pinning

Every target carries an `image_digest` in `targets.json`. The invariant
`blocking ⇒ pinned` is enforced two ways:

- `TestShippedBlockingTargetsArePinned` (unit, no Docker) fails the build if a
  target is marked blocking without a digest.
- `Target.RequirePin()` fails the leg at run time with the command to fix it.

All four legs ship **unpinned and non-blocking**, which is RFC-0149 §10.1's
Phase 3 state. Promoting the two LTS legs (Phase 4) means running
`make pin-ubuntu-matrix`, flipping `blocking` to `true` in `targets.json`, and
changing branch protection — and the invariant above makes it impossible to do
the second without the first.

## Coverage policy

`targets.json`'s `policy` block is the `DistributionSupportPolicy` (§4.1.5) —
the single place that answers "why is / isn't version X in the matrix" without
reading CI YAML. `Matrix.Validate()` enforces it: declaring fewer supported LTS
targets than `min_lts_versions_covered` is an error naming
`software_lifecycle` (`vendor='canonical'`, `product='ubuntu_linux'`), which is
the dataset a reviewer should re-check membership against (R4).

## Downstream

`.matrix-reports/<slug>.json` is the §5.4 ingest payload. The trusted-zone
`ubuntu-package-matrix-ingest.yml` workflow signs it with HMAC-SHA256 and POSTs
it to `POST /kite-collector/package-matrix-result`, which materialises it into
`kite_os_distribution_targets`, `kite_container_test_fixtures`,
`kite_package_discovery_test_runs`, `kite_package_parity_findings` and the
shared ontology.

Ingestion is decoupled and best-effort by design: GitHub's own status check is
the sole merge signal, so a worker outage degrades observability and never
mergeability.
