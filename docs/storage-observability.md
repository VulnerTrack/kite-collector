# Storage observability

The collector records every mounted filesystem on the local host — capacity,
usage, inodes and encryption posture — into `host_volumes`, and the dashboard's
**Volumes** page (`/volumes`) renders it fleet-wide, joined to the machine that
owns each mount.

## What is collected

One row per `(machine_id, mount_point)`:

| Field | Source | Notes |
|---|---|---|
| `device`, `filesystem`, `mount_opts`, `label`, `fs_uuid` | gopsutil `disk.Partitions` | pseudo filesystems (tmpfs, proc, cgroup) are excluded |
| `size_bytes`, `used_bytes` | gopsutil `disk.Usage` (statfs) | `NULL` when the mount can't be stat'd |
| `inodes_total`, `inodes_used` | same | `NULL` on filesystems that don't expose inode counts — btrfs, vfat, APFS |
| `encryption`, `encryption_state` | per-OS probe | LUKS via `/proc/crypto` (Linux), BitLocker via WMI (Windows), FileVault via `fdesetup` (macOS) |
| `read_only`, `removable`, `bootable` | mount opts + path heuristics | feed the CWE-311 "unencrypted boot volume" query |

Collection is strictly read-only: it queries mount tables and metadata, and
never mounts, unmounts, formats or modifies a volume.

## Cadence

A dedicated ticker refreshes storage every **5 minutes**
(`hostVolumesInterval` in `cmd/kite-collector/main.go`), independent of the
discovery scan. Capacity is a metric, not inventory — the 6-hour default scan
cadence would leave "is anything about to fill up?" up to six hours stale. A
cycle costs one partition walk plus a `statfs` per mount.

The cycle runs off the main loop with drop-on-busy semantics: `statfs` on a
wedged NFS mount blocks uninterruptibly in the kernel, and that must never stall
a discovery scan. A skipped tick is harmless because each sample re-reads
absolute values rather than deltas.

## Write semantics

`ReplaceHostVolumes` is **upsert-plus-prune**, not delete-then-insert (which is
what the sibling `ReplaceHostListeners` does):

- A mount that is still present keeps its row identity, so the capacity
  timeline stays attached to one row.
- Mounts that have disappeared are deleted, so an unplugged USB disk doesn't
  linger as a stale row. Pruning keys on `collected_at` — every row a pass
  touched carries that pass's timestamp — which avoids an `IN (...)` list that
  would exceed the SQLite variable limit on a storage server near
  `volumes.MaxVolumes` (1024) mounts.
- `synced_at` is reset to `NULL` on every upsert: capacity is time-varying, so
  a rescan genuinely produces new data for the sync bridge to ship.

A collect that returns rows *and* an error persists the partial inventory —
gopsutil reports per-mount permission failures on macOS system volumes even as
root, and the alternative is a page that empties out whenever one mount
misbehaves. A collect that returns **no** rows never reaches the store, so a
transient failure can't prune a machine's entire volume set.

## Reading it on the dashboard

`/volumes` shows Size, Used, a Usage bar and an Inodes bar per mount, with the
in-place facet rail over filesystem, encryption state, read-only, removable and
bootable. Usage bars are tinted at the thresholds in `ratioBar()`
(`internal/dashboard/host_tables_page.go`): **warn at 75%, critical at 90%**.

A mount with no measurement renders as `—`, never as `0 B` — "we couldn't stat
it" and "it's empty" are different facts.

## Related signals

`system.disk.usage` and `system.disk.utilization` are emitted over OTLP every
60s by `internal/telemetry/hostmetrics` when streaming is configured. That is
the high-frequency, external-observability path; `host_volumes` is the durable,
local, queryable one that the dashboard and the CWE audit pipeline read.

Log codes: `agent.host_volumes.configured`, `agent.host_volumes.collect_failed`,
`agent.host_volumes.collect_degraded` (see [LOG_CODES.md](LOG_CODES.md)).
