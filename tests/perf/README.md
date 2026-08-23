# Dashboard render check (offline)

A browser test that verifies the collector dashboard's `/machines` page renders
**fast and fully offline**, and measures the render timings.

It exists to guard the render fix in `internal/dashboard/page.go`: the page must
not block first paint on an external font/CDN, and must become interactive with
no internet at all — a loopback security dashboard has to be self-contained.

## What it verifies

Driving the **system browser** via `playwright-core` (no Playwright browser
download), with **every non-loopback request aborted**:

- `/machines` reaches an interactive grid with all external requests blocked —
  the offline / self-contained guarantee. If the page needed the internet to
  become usable, it would time out here.
- No **render-blocking external stylesheet** is present (the Inter web font must
  load via the `media="print"` swap, or be self-hosted). A plain blocking
  `<link>` fails the check.
- `grid-ready` stays under a budget (default 5000 ms).

It reports the median and per-run values for: server `responseEnd`,
first-contentful-paint, `DOMContentLoaded`, `load`, grid-interactive, and the
external origins the page tried to reach (all blocked).

## Run

```bash
# Builds the collector, boots a throwaway dashboard on loopback, runs the check:
./run.sh
```

The run is fully offline. The **only** step that needs the network is the
one-time `npm install` of `playwright-core` (small; it does not download a
browser — the host's chromium/chrome is used at run time). After that,
`node_modules/` is cached and nothing reaches the internet.

### Against an already-running dashboard (e.g. the live one, with a real fleet)

```bash
node machines-render.test.mjs http://127.0.0.1:9090
```

Row-scaling costs (the Tabulator layout) only show up with a populated
inventory, so this is the way to measure with real data. `run.sh`'s throwaway
dashboard starts empty, which is fine for the behavior check.

## Knobs

| Env | Default | Meaning |
|-----|---------|---------|
| `KITE_CHROME` | autodetect (`/bin/chromium`, `google-chrome-stable`, …) | browser binary to drive |
| `KITE_RENDER_BUDGET_MS` | `5000` | grid-ready budget; the check fails above it |
| `KITE_RUNS` | `3` | measured iterations (median reported) |
| `KITE_PORT` | `9096` | loopback port for `run.sh`'s throwaway dashboard |

## Requirements

- Node (for the harness) and a chromium/chrome binary already on the host.
- Go (only for `run.sh`, which builds the collector).
