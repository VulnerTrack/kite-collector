# Container observability

The dashboard's **Containers** page gives live observability over the local
Docker / Podman / docker-compose environment — no external tooling, no JS
charting library, no Docker SDK. The design ports lazydocker's three headline
capabilities into the dashboard's HTMX + server-rendered-SVG idiom:

1. **State at a glance** — every container with an icon status + parsed
   health, grouped by compose project, auto-refreshing.
2. **Custom metric graphs** — sparkline columns for any numeric metric the
   Engine reports, selected by dotted *stat path*.
3. **Image ancestor layers** — `docker history` for any image, from the
   image inventory or straight from a container row.

Open it at `http://<dashboard>/containers` (also in the sidebar under
*Views → Containers*).

## Engine resolution

The page talks to the first engine it finds, in this order:

1. `discovery.sources.docker.host` from the agent config
2. the `KITE_DOCKER_HOST` environment variable
3. socket autodetection: `/var/run/docker.sock`,
   `/run/podman/podman.sock`, rootless Podman, or the Docker Desktop
   named pipe / `tcp://localhost:2375` on Windows

All communication is plain HTTP against the Engine API (`v1.43`), reusing
the same transport as the `docker` discovery source.

## State at a glance

Containers are grouped by their `com.docker.compose.project` label
(standalone containers get their own bucket). Each row shows:

| Column | Source |
|---|---|
| state icon | `State` + health parsed from the summary `Status` text (`✔` healthy, `✖` unhealthy/dead, `◐` health starting, `▶` running, `⏸` paused, `↻` restarting, `■` exited) |
| name / service | container name + compose service label |
| status | the daemon's human status ("Up 3 hours (healthy)") |
| image | links to the image's ancestor layers |
| ports, created | summary fields |
| metric columns | see below |

The summary chips at the top (total / running / unhealthy / exited /
compose projects) answer "is my stack up?" without reading the table.

The fragment auto-refreshes every 10 s; the **Pause** chip freezes it while
you inspect a row (state lives in the URL as `?paused=1`, like the
observability page).

## Custom metric graphs

Two metric columns are always on: **CPU %** and **Memory %**. Both follow
the `docker stats` math:

- CPU % is derived from *consecutive one-shot samples* (Δcontainer-cpu ÷
  Δsystem-cpu × online CPUs × 100) — the same technique lazydocker applies
  to its stats stream. The first sample has no baseline, so cells show `…`
  until the second poll (5 s).
- Memory subtracts the page cache (`inactive_file` /
  `total_inactive_file`) before dividing by the limit, so the number
  matches `docker stats`, not the raw cgroup counter.

To graph **any other metric**, add a column by *stat path* — a dotted path
into the Engine stats document:

```
pids_stats.current
memory_stats.stats.pgmajfault
networks.eth0.rx_bytes
blkio_stats.io_service_bytes_recursive   ← arrays are NOT addressable; pick scalar leaves
```

Derived metrics are namespaced under `derived.`:
`derived.cpu_percent`, `derived.memory_percent`, `derived.memory_bytes`,
`derived.memory_limit_bytes`, `derived.net_rx_bytes`,
`derived.net_tx_bytes`, `derived.pids`. Network totals are summed across
**all** interfaces (lazydocker hardcodes `eth0`), and note they are
cumulative counters — the *slope* of the sparkline is the throughput.

Three ways to add a column:

1. Type the path into the **Add metric column** form.
2. Open a container's **Graphs** drawer and browse *All stat paths* — every
   numeric leaf of the latest raw sample with its current value and a
   *Graph* link. This is the discovery surface: no docs required to know
   what your engine version exposes.
3. Edit the URL: `/containers?graph=pids_stats.current&graph=memory_stats.stats.pgmajfault`.

The custom view lives entirely in the URL — **bookmark it** to keep a
purpose-built board (e.g. a "memory pressure" view with `pgmajfault` +
`memory_stats.stats.active_anon`). The JSON snapshot link carries the same
columns for scripted monitoring:

```
GET /api/v1/containers/snapshot.json?graph=pids_stats.current
```

### Collection model

A background monitor samples one-shot stats for every running container
each 5 s (bounded parallelism), keeping a 10-minute ring buffer per metric
per container. It starts on the first page view and **stops itself after
3 minutes without a viewer** — the agent stays quiet when unobserved.
Custom paths nobody has rendered for 10 minutes are evicted. History is
in-memory only and resets with the process, by design.

## Image ancestor layers

The **Images** card lists the local inventory (largest first). *Layers* —
on an image row or on any container's image link — opens the ancestor
chain in the drawer: every instruction that built the image, newest first,
with per-layer size, creation time, and tags. Shell wrappers are trimmed
(`/bin/sh -c #(nop) CMD …` → `CMD …`, `/bin/sh -c foo` → `RUN foo`); hover
shows the untrimmed command. `<missing>` rows are intermediate layers whose
IDs the daemon no longer tracks — normal for pulled images.

## Failure modes

- **No engine found** → the page renders a hint card (config →
  `KITE_DOCKER_HOST` → sockets) instead of an error page.
- **Engine dies mid-session** → the list render surfaces the error; the
  monitor logs `dashboard.containers.list_failed` and keeps retrying until
  idle-stop.
- **Invalid stat path** → rejected with an inline explanation; paths are
  validated (dotted `[A-Za-z0-9_-]` segments, ≤128 chars, ≤8 custom
  columns) before they reach the monitor.
