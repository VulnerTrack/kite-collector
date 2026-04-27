# Telemetry Contract v1.0

> **What this is:** the closed list of every piece of information `kite-collector` is permitted to send to the central OpenTelemetry collector.
>
> **Authoritative source:** [`internal/telemetry/contract/v1.go`](../internal/telemetry/contract/v1.go) (Go) and [`internal/telemetry/contract/v1.json`](../internal/telemetry/contract/v1.json) (JSON Schema 2020-12).
>
> **Specification:** [RFC-0115](../../../docs/rfcs/agent-to-central-otel-telemetry-contract.md).

The contract is enforced at the agent before any data leaves the host. Any attribute key not declared here is dropped at the OTLP emitter (`internal/emitter/otlp.go`) and again at the OTel Collector's `filter/contract` processor.

---

## Quick reference

| Channel | What it carries | Today | Target (RFC-0115 §4) |
|---------|-----------------|-------|----------------------|
| **Resource attributes** | Agent identity, host, OS, contract version | 15-key set per §4.2 | Same |
| **Log records** | Asset lifecycle + finding events | `kite.asset.*` event names from the legacy hand-rolled emitter | Five `event.name`s under `event.domain=security` |
| **Trace spans** | Scan execution timing | Not emitted yet | Closed span set rooted at `scan` |
| **Metrics** | Operational counters / histograms | Prometheus only on `:9090` | Catalog of 14 OTLP instruments |

Trace spans and OTLP metrics are deferred to RFC-0073 (the OTel SDK migration); the resource attribute set and the log-record forbidden-key policy are live as of v1.0.

---

## Resource attributes (every signal carries these)

| Key | Type | Privacy | Source | Constant value |
|-----|------|---------|--------|----------------|
| `service.name` | string | public | constant | `kite-collector` |
| `service.version` | string | public | build flag | — |
| `service.namespace` | string | public | constant | `vulnertrack` |
| `service.instance.id` | UUIDv7 | host-identifying | persistent agent identity | — |
| `host.id` | string | host-identifying | `/etc/machine-id` (Linux) or hostname fallback | — |
| `host.name` | string | host-identifying | `os.Hostname()` | — |
| `host.arch` | string | public | `runtime.GOARCH` | — |
| `os.type` | string | public | `runtime.GOOS` | — |
| `os.name` | string | public | `/etc/os-release` `ID=` | — |
| `os.version` | string | public | `/etc/os-release` `VERSION_ID=` | — |
| `agent.id` | UUIDv7 | host-identifying | mirror of `service.instance.id` for query convenience | — |
| `agent.type` | string | public | constant | `kite-collector` |
| `tenant.id` | UUIDv7 | tenant-scoped | `KITE_TENANT_ID` env var; **overridden** at the Collector from the mTLS Subject CN | — |
| `deployment.environment` | string | public | `KITE_DEPLOYMENT_ENVIRONMENT` env var | one of `production`, `staging`, `pilot`, `development` |
| `kite.contract.version` | string | public | constant | `1.0` |

> **`tenant.id` is client-asserted but not trusted.** The Collector overwrites it from the agent's mTLS client certificate Subject CN per RFC-0115 §5.1. Treat the agent-provided value as a hint only.

---

## Forbidden keys (never leave the agent)

The redactor at [`internal/telemetry/redact/redact.go`](../internal/telemetry/redact/redact.go) drops any key matching:

- **Substrings** (case-insensitive): `password`, `passwd`, `secret`, `apikey`/`api_key`/`api-key`, `private_key`/`privatekey`/`private-key`, `authorization`, `auth_token`/`authtoken`, `bearer`, `session_id`/`sessionid`, `cookie`
- **Exact** keys: `env`, `environ`, `command`, `cmdline`, `argv`, `token`, `key`
- **Prefixes**: `internal.`, `debug.`, `env.`, `environ.`

The substring check is intentionally aggressive. Resource attributes that legitimately contain `id`/`uid` (`service.instance.id`, `agent.id`, `host.id`, `tenant.id`, `security.scan.uid`, `security.asset.uid`, `security.finding.uid`) are explicitly allow-listed.

If you need to add a new attribute that contains one of those substrings, edit `allowedSensitiveKeys` in `redact.go` and document the rationale in the same change.

---

## Log records (target: §4.4)

Five event names under `event.domain = "security"`:

| Event name | Triggered by | Required attributes |
|------------|--------------|---------------------|
| `asset.discovered` | First time an asset enters the inventory | `security.asset.{uid,type,name,authorization,managed_status,first_seen,discovery.source}`, `security.scan.uid` |
| `asset.changed` | Authorization, managed status, or last-seen change | `security.asset.{uid,type,name,authorization,managed_status,change.field}`, `security.scan.uid` |
| `finding.configuration` | Audit module finds a misconfiguration | `security.finding.{uid,type,title,severity,severity_id}`, `security.asset.{uid,name}`, `security.scan.uid` |
| `finding.posture` | Posture analysis finds a CAPEC pattern | `security.finding.{uid,type,title,severity,severity_id,likelihood}`, `security.asset.{uid,name}`, `security.scan.uid` |
| `scan.lifecycle` | Coarse-grained lifecycle marker | `security.scan.{uid,phase}` |

See [`internal/telemetry/contract/golden/`](../internal/telemetry/contract/golden/) for one canonical fixture per event.

> **Current emitter status:** the live agent emits the legacy `kite.asset.{discovered,updated,unauthorized_detected,unmanaged_detected,not_seen,removed}` event names with snake_case attribute keys (`asset_id`, `scan_run_id`, `is_authorized`, …). RFC-0083's ingest workflow keys on those names. The OCSF re-shape lands as part of the v1 cutover with a coordinated dual-emit window.

---

## Spans (target: §4.5)

Spans land when the SDK migration (RFC-0073) ships. The closed span set:

```
scan                                 (root, one per scan)
├── discover                         ┐
│   ├── discover.agent               │
│   ├── discover.docker              │
│   ├── discover.cloud.aws           │ enums in v1.go
│   ├── discover.vpn.tailscale       │ AllowedDiscoverySources
│   └── discover.<source>            ┘
├── dedup
├── classify
├── audit
│   ├── audit.ssh                    ┐
│   ├── audit.firewall               │ enums in v1.go
│   ├── audit.permissions            │ AllowedAuditModules
│   └── audit.tls                    ┘
├── posture
├── policy
├── persist
└── emit
```

---

## Metrics (target: §4.6)

14 instruments in the catalog; see `Metrics` in `v1.go`:

```text
kite.scan.duration              histogram   s         labels: scan.type, status
kite.scan.runs.count            counter     {scan}    labels: scan.type, status
kite.discovery.duration         histogram   s         labels: discovery.source
kite.discovery.assets.found     counter     {asset}   labels: discovery.source
kite.discovery.errors.count     counter     {error}   labels: discovery.source, error.kind
kite.assets.total               up_down     {asset}   labels: asset.type, authorization
kite.assets.stale               up_down     {asset}
kite.findings.count             counter     {finding} labels: finding.type, severity
kite.findings.open              up_down     {finding} labels: severity
kite.events.emitted.count       counter     {event}   labels: event.name
kite.otlp.export.duration       histogram   s         labels: signal, status
kite.otlp.export.bytes          counter     By        labels: signal
kite.otlp.queue.size            up_down     {record}  labels: signal
kite.otlp.dropped.count         counter     {record}  labels: signal, reason
```

`signal` is one of `logs`, `traces`, `metrics`.

---

## Cardinality budgets

The Collector enforces these per-tenant per-day distinct-value caps; above the cap the offending key is rewritten to `_overflow_` and `kite.cardinality.alert` is emitted.

| Key | Budget |
|-----|--------|
| `security.finding.cwe.uid` | 1 500 |
| `security.finding.capec.uid` | 600 |
| `security.asset.uid` | 1 000 000 |
| `security.asset.fqdn` | 200 000 |
| `security.scan.uid` | 100 000 |
| `discovery.source` | 16 (closed enum) |
| `audit.module` | 16 (closed enum) |
| `event.name` | 5 (closed enum) |

---

## Versioning

```
v1.0  — this document; frozen at agent v0.5.x
v1.x  — purely additive: new MAY attributes, MAY span attributes, metric labels
v2.0  — breaking: removal/rename of MUST attributes, enum semantic change, event removal
        Requires a 90-day dual-emit window (RFC-0115 §2.3).
```

Bumping the contract = editing **both** [`v1.go`](../internal/telemetry/contract/v1.go) and [`v1.json`](../internal/telemetry/contract/v1.json) plus the matching golden fixtures, in one PR. The contract test (`go test ./internal/telemetry/contract/...`) fails when the two artifacts disagree.
