# osquery on macOS

kite-collector's osquery discovery source reads host identity, listening
ports, YARA scan results, and file-integrity events from a local `osqueryd`
over its Thrift extensions socket. This page covers the macOS lane: how the
daemon gets there, where kite talks to it, and the one macOS-specific way a
green result can still be wrong.

For the source itself — the socket precedence, the YARA credential proofs, the
error contract — see RFC-0151 in the monorepo
(`docs/rfcs/osquery-backed-discovery-yara-fim-integration-for-kite-collector.md`).

## Why macOS is different

On Linux and Windows kite ships osqueryd itself: the `kite-collector-osquery`
deb and MSI carry a checksum-pinned payload and register it as the
`kite-osqueryd` service.

macOS does not get a vendored payload, and the reason is signing rather than
packaging. A macOS artifact carrying osqueryd would have to be Developer
ID-signed and notarized as one unit, and the daemon would then run under
kite's signature — which also means it would need **kite's** Full Disk Access
grant rather than osquery's. Adopting the operator's own
`/opt/osquery/lib/osquery.app` keeps the daemon signed and TCC-attributed to
osquery, exactly as `osqueryctl start` would run it.

So on macOS: **osquery's binary stays osquery's.** kite owns only the
configuration, the state directory, and the launchd job — all namespaced under
`kite-osqueryd` so they can never collide with the `io.osquery.agent` job the
osquery pkg registers.

## Two supported shapes

### 1. Your own osqueryd, no kite setup

If you already run osquery's own daemon, kite finds it and nothing else is
needed:

```bash
brew install --cask osquery      # or the pkg from https://osquery.io/downloads
sudo osqueryctl start            # loads io.osquery.agent
```

Discovery auto-detects `/var/osquery/osquery.em` on the next scan. Confirm
with `kite-collector doctor`.

### 2. A kite-configured daemon

If you want osquery configured *for* kite — the FIM/YARA-ready flags, the
namespaced state directory, kite's own socket — register the sibling daemon:

```bash
brew install --cask osquery
sudo kite-collector install --with-osquery
```

That registers `kite-osqueryd` as a system launchd daemon pointing at the
osqueryd binary you already have. Preview it first with
`kite-collector install --with-osquery --dry-run`, which runs detection for
real and prints the daemon path it found.

The two shapes can coexist: `kite-osqueryd` and `io.osquery.agent` are
separate jobs with separate sockets, databases, and log directories.

## What `--with-osquery` creates

| Path | Owner | Purpose |
|---|---|---|
| `/Library/LaunchDaemons/kite-osqueryd.plist` | kite | The launchd job |
| `/var/kite-osquery/kite-osquery.em` | kite | Extensions socket |
| `/var/lib/kite-collector/osquery/osquery.conf` | you, after first write | Schedule, packs, FIM paths |
| `/var/lib/kite-collector/osquery/osquery.flags` | you, after first write | Behavioral flags |
| `/var/lib/kite-collector/osquery/osquery.db` | osqueryd | RocksDB state |
| `/var/lib/kite-collector/osquery/logs/` | osqueryd | Result and status logs |
| `/opt/osquery/lib/osquery.app/…/osqueryd` | **osquery** | The daemon binary — kite never writes here |

Path flags (`--config_path`, `--database_path`, `--logger_path`,
`--extensions_socket`) ride the launchd job's `ProgramArguments`, not the
flagfile, so a relocated install keeps working. Inspect them with:

```bash
sudo launchctl print system/kite-osqueryd
plutil -p /Library/LaunchDaemons/kite-osqueryd.plist
```

### The socket is not under /var/run

`/var/kite-osquery/` looks unusual next to the Linux
`/run/kite-osquery/`. macOS has no `/run` at all, and its `/var/run` is
emptied on every boot — a socket directory created once at install time would
be gone after the first restart, and launchd would restart the daemon into the
same bind failure forever. `/var/kite-osquery` mirrors the `/var/osquery`
directory osquery's own pkg creates: persistent, root-owned, namespaced.

### Your edits survive upgrades

`osquery.conf` and `osquery.flags` are written once. A later
`install --with-osquery` leaves existing files alone and says so — they are
where FIM `file_paths` and YARA rules get armed, and an upgrade that silently
reverted those edits would disarm monitoring you deliberately turned on.
Delete a file to get the shipped default back.

## Full Disk Access — the macOS silent-zero trap

**A clean osquery result on macOS does not mean a clean host.**

macOS TCC gates reads of protected locations: Mail, Messages, Safari data,
Time Machine backups, other users' home directories, and the TCC database
itself. A daemon without Full Disk Access does not get an error when it reads
one of those — it gets **fewer rows**. An ungranted host therefore looks
exactly like a spotless one.

This is the same shape as the YARA silent-zero contract the discovery source
already defends against (a missing sigfile, an uncompilable rule, and a
missing scan target all return rc 0 with zero rows), except that this one is
enforced by the OS and cannot be proven or disproven over the extensions
socket. kite cannot detect it for you.

Grant it once:

1. **System Settings → Privacy & Security → Full Disk Access**
2. **+**, then `⌘⇧G` and enter `/opt/osquery/lib/osquery.app`
3. Restart the daemon: `sudo launchctl kickstart -k system/kite-osqueryd`
   (or `sudo osqueryctl restart` for osquery's own job)

Both jobs execute the same signed binary, so one grant covers both.

Under MDM, deliver this as a PPPC (Privacy Preferences Policy Control) payload
targeting the osquery app bundle's code-signing requirement rather than asking
each user to click through Settings.

## FIM and YARA

Both ship **off**: `osquery.flags` sets `--enable_file_events=true` so the
subscriber exists, but `osquery.conf` configures no `file_paths`, so no
watches are armed and an install that did not ask for FIM costs nothing at
rest. Uncomment the `file_paths` block in `osquery.conf` to turn it on.

Keep FIM categories **disjoint** from any `yara_events` `file_paths`. On Linux
that is load-bearing: the inotify publisher binds each kernel watch to exactly
one subscriber, so an overlapping `yara_events` category silently steals the
watch and FIM goes deaf with no error anywhere. macOS uses the FSEvents
publisher instead, so the mechanism differs — but overlapping categories are
untested there and not worth the risk.

On-demand YARA scans are configured on the kite side, not in `osquery.conf` —
`sources.osquery.yara_paths` plus either `yara_rules` (inline) or
`yara_sigfile` (a path the *daemon* can see). The source proves the credential
is usable before trusting a zero-row answer.

## Diagnosing

```bash
kite-collector doctor
```

The `osquery` stage reports which socket discovery would use and whether
anything answers on it. It never fails the run — osquery is optional
everywhere, and a host without it is a supported configuration.

| What you see | What it means |
|---|---|
| `pass — daemon answering on …` | Discovery will read this daemon on the next scan |
| `skip — no osqueryd on this host` | Nothing installed; the source no-ops |
| `skip — osqueryd present … but no extensions socket is listening` | Installed but not running |
| `warn — socket … did not answer` | Stale socket from a daemon that died, or one still booting |

Then, in order of usefulness:

```bash
sudo launchctl print system/kite-osqueryd        # job state, last exit status
sudo osqueryi --socket /var/kite-osquery/kite-osquery.em   # talk to it yourself
tail -f /var/lib/kite-collector/osquery/logs/osqueryd.INFO
```

## Removal

```bash
sudo kite-collector uninstall
```

This deregisters `kite-osqueryd` along with the collector. The state directory
is left in place, so a re-install keeps your `osquery.conf` edits and the FIM
event history the daemon buffered. Your osquery install is untouched — kite
never owned it.
