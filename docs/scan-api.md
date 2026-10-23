# Scan API

When the agent runs in long-lived mode (`agent --stream` or `agent` with the
REST server enabled), scans can be triggered, watched, and cancelled over HTTP
instead of SSH-ing to the host to run `kite-collector scan`. The dashboard uses
the same endpoints.

All routes sit behind the `MTLSOrAPIKey` middleware (RFC-0063): when an API
key is configured (`fleet.api_key`) every request must present it via
`X-API-Key` or a valid mTLS client certificate. The server listens on
`127.0.0.1:8080` by default (`api.addr` / `KITE_API_ADDR`); binding it beyond
loopback without `fleet.api_key` leaves it unauthenticated, and the agent logs
`agent.api.unauthenticated_exposed` at startup.

Only one scan runs at a time. A second `POST /api/v1/scans` while a scan is
already running returns `409 Conflict` with the active scan's id, so callers
can poll it instead of retrying blindly.

## Trigger a scan

```bash
# Minimal trigger — uses the operator-declared config as-is.
curl -sS -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: $KITE_API_KEY"

# 202 Accepted
# Location: /api/v1/scans/019515a1-7f42-7f0a-8a1c-...
# {"scan_run_id":"019515a1-7f42-7f0a-8a1c-..."}
```

Narrow the run to a subset of declared sources (sources must already be
enabled in the config — the endpoint cannot widen scope):

```bash
curl -sS -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: $KITE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sources": ["network", "docker"]}'
```

mTLS variant (no API key; client cert authenticates the caller):

```bash
curl -sS -X POST https://kite.internal:8443/api/v1/scans \
  --cert /etc/kite/tls/client.crt \
  --key  /etc/kite/tls/client.key  \
  --cacert /etc/kite/tls/ca.crt
```

## Inspect and follow a scan

```bash
# Snapshot of a specific run.
curl -sS http://localhost:8080/api/v1/scans/$ID -H "X-API-Key: $KITE_API_KEY"

# Live progress via Server-Sent Events. --no-buffer disables curl's line
# buffering so status/progress/done frames land as soon as the agent emits
# them; the stream closes on terminal status.
curl -sS --no-buffer http://localhost:8080/api/v1/scans/$ID/events \
  -H "X-API-Key: $KITE_API_KEY"

# event: snapshot
# data: {"id":"...","status":"running", ...}
#
# event: progress
# data: {"scan_run_id":"...","type":"progress", ...}
#
# event: done
# data: {"scan_run_id":"...","type":"done", ...}
```

## Cancel a running scan

```bash
curl -sS -X POST http://localhost:8080/api/v1/scans/$ID/cancel \
  -H "X-API-Key: $KITE_API_KEY"

# 202 Accepted
# {"scan_run_id":"...","cancel_requested_at":"2026-04-21T14:47:36Z"}
```

The scan row is stamped with `cancel_requested_at` and the engine finalises
the run as `timed_out` once it honours the cancellation (typically at the
next source boundary).

## Kill switch

Set `KITE_COLLECTOR_SCAN_API=off` to force the trigger/cancel/SSE endpoints
to return `503 Service Unavailable` and make the dashboard "Run Scan" button
fall back to a read-only badge. Useful as a rollback knob without a redeploy.

The dashboard's scan-status badge polls `/fragments/scan-status` every three
seconds, so a run started from "Run Scan" moves through
`running → completed / failed / timed_out` without a manual reload.
