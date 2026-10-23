# Streaming to OpenTelemetry

kite-collector pushes machine lifecycle events to any OTLP-compatible
collector (Grafana Alloy, OpenTelemetry Collector, Datadog Agent, etc.) as
**OTLP log records over HTTP/JSON**, sent to `<endpoint>/v1/logs` as each scan
cycle generates them. Attribute names, event types and severities are
specified in the [telemetry contract](telemetry-contract.md). A runnable
collector plus Compose file lives in
[examples/streaming-to-otel/](../examples/streaming-to-otel/).

## Quick start

```yaml
streaming:
  interval: 6h
  otlp:
    endpoint: http://localhost:4318
    protocol: http
```

```bash
kite-collector agent --stream --interval 6h
```

Or skip the config file with `KITE_`-prefixed environment variables:

```bash
export KITE_STREAMING_OTLP_ENDPOINT=http://otelcol:4318
export KITE_STREAMING_OTLP_PROTOCOL=http
kite-collector agent --stream
```

## Mutual TLS

```yaml
streaming:
  otlp:
    endpoint: https://otelcol.internal:4318
    protocol: http
    tls:
      enabled: true
      cert_file: /etc/kite/tls/client.crt
      key_file: /etc/kite/tls/client.key
      ca_file: /etc/kite/tls/ca.crt
```

## Payload authenticity and integrity

mTLS proves *the channel* was opened by a valid client. It says nothing about
the bytes once TLS is terminated — by a CDN, a load balancer, a debugging
proxy, or anyone holding a stolen session. RFC-0072 §4.8 closes that gap by
protecting the payload itself, in two modes that share one signing credential:
the enrolled client certificate.

| | `signing` | `encryption` |
| --- | --- | --- |
| Authenticity — these bytes came from this certificate | ✅ | ✅ |
| Integrity — nothing altered them in transit | ✅ | ✅ |
| Non-repudiation — the agent cannot disown the batch | ✅ | ✅ |
| Confidentiality — a TLS terminator cannot read them | — | ✅ |
| Works with a stock OpenTelemetry Collector | ✅ | ❌ needs an unwrapping gateway |

Pick `signing` unless the payload must also be unreadable to whatever
terminates TLS. They are mutually exclusive; enabling both is a config error,
because the envelope already signs its inner payload. Both are separate from
the per-record Ed25519 signature every log record carries regardless of
configuration ([telemetry contract § Record signature](telemetry-contract.md#record-signature-v13-additive-always-on)).

### Signed bodies (`signing`)

The body stays byte-for-byte the OTLP/JSON it would otherwise have been, and a
**detached JWS** over it travels in a header. A receiver that knows nothing
about signatures ingests the batch normally; one that checks the header learns
which certificate produced those exact bytes. That asymmetry is the point:
signing can be turned on across a fleet today and verified server-side
whenever the receiving end is ready.

```yaml
streaming:
  otlp:
    endpoint: https://otel.vulnertrack.io
    tls:
      enabled: true
      cert_file: /var/lib/kite-collector/<agent-code>/agent.pem
      key_file: /var/lib/kite-collector/<agent-code>/agent-key.pem
      ca_file: /var/lib/kite-collector/<agent-code>/ca.pem
    signing:
      enabled: true
      # Optional. Drops x5c from the signature when the receiver already
      # holds the agent certs and the ~1.5 KB per request matters.
      omit_certificate_chain: false
```

What goes on the wire when `signing.enabled` is true:

| Aspect | Plain | Signed |
| --- | --- | --- |
| Body | OTLP/JSON | **identical** OTLP/JSON |
| `Content-Type` | `application/json` | `application/json` |
| Extra headers | — | `X-Kite-Envelope-Signature` (detached JWS), `X-Kite-Envelope-Signer` (`kid`) |
| Signature | — | `alg` from the key type, `kid`, `cty: application/json`, `x5c` + `x5t#S256`, plus `iat` and `jti` |

The signature is `<protected>..<signature>` — RFC 7515 Appendix F, with the
payload segment empty because the payload is the HTTP body. To verify:
base64url-encode the received body, splice it into the middle segment, and
check the JWS; `envelope.VerifyDetached` does this and returns the certificate
chain for the caller to validate against the PKI CA.

`tenant.id` stays server-authoritative exactly as on the plain path: the
receiver reads it from the verified certificate's Subject Organization, never
from the body.

Signatures are per batch, so one signature covers every log record in the
request. It is computed once and reused across retries — a redelivery is the
same bytes, not a new claim. Each new batch carries a fresh `jti` nonce and an
`iat` timestamp, which is what lets a receiver reject a replayed batch: a
signature over captured bytes stays valid forever, so only a nonce cache or a
freshness window can tell a resend from the original.

The signature is sized by the certificate chain, not the body — roughly
1.5–2.5 KB with `x5c`, a few hundred bytes without. A chain that would not fit
an HTTP header line is rejected when the signer is built, not on the first
send.

### Enveloped bodies (`encryption`)

Every request body is **JWS-signed with the agent's client certificate key**
and then **JWE-encrypted to the receiver's public key** before it leaves the
process, so a TLS terminator sees only ciphertext.

```yaml
streaming:
  otlp:
    endpoint: https://otel.vulnertrack.io
    tls:
      enabled: true
      cert_file: /var/lib/kite-collector/<agent-code>/agent.pem
      key_file: /var/lib/kite-collector/<agent-code>/agent-key.pem
      ca_file: /var/lib/kite-collector/<agent-code>/ca.pem
    encryption:
      enabled: true
      server_jwk_url: https://otel.vulnertrack.io/.well-known/jwks.json
      # Optional; the only supported suite. Anything else is rejected at load.
      algorithm: ECDH-ES+A256KW
      content_encryption: A256GCM
```

What goes on the wire when `encryption.enabled` is true:

| Aspect | Plain | Enveloped |
| --- | --- | --- |
| Body | OTLP/JSON | Compact JWE (5 segments) whose plaintext is a compact JWS whose payload is the OTLP/JSON |
| `Content-Type` | `application/json` | `application/jose` |
| Extra headers | — | `X-Kite-Envelope-Key-Id` (receiver JWK `kid`), `X-Kite-Envelope-Signer` (inner JWS `kid`) |
| Inner JWS | — | `alg` from the key type (`ES256` for the PKI-issued P-256 cert, `EdDSA` for the identity key), `kid`, `cty: application/json`, and `x5c` + `x5t#S256` carrying the client certificate |
| Outer JWE | — | `alg: ECDH-ES+A256KW`, `enc: A256GCM`, `kid` of the receiver key |

The receiver key comes from `server_jwk_url` (a standard JWKS document; the
first `use: enc` key is used), cached for an hour and reused if a refresh
fails.

**A stock OpenTelemetry Collector cannot read enveloped bodies.** Enable this
only when a gateway that decrypts and verifies the envelope fronts the
collector. The OTLP ping in `kite-collector doctor` still sends plain JSON, so
a gateway that only accepts `application/jose` reports the ping as rejected.

### The signing credential (both modes)

The client certificate under `streaming.otlp.tls` when one is configured — the
same `agent.pem` / `agent-key.pem` the transport presents, so "the cert signs
the payload" holds literally and the receiver verifies against the `x5c` chain
it already trusts, with no key registry. Otherwise the `identity.json` Ed25519
key signs, with the agent ID as `kid`, and the receiver must know that public
key by agent (logged as `agent.telemetry.envelope_identity_signer`).

A cert/key pair whose public halves disagree is rejected at start-up, so a
half-rotated certs directory fails loudly instead of emitting signatures
nobody can verify. Turning on either mode with no credential available is
likewise a start-up error, never a silent fallback to unprotected telemetry —
and if signing or sealing fails at send time the batch is not sent, it is
spooled.

Both the `/v1/logs` and `/v1/metrics` signals, the scan-summary aggregate, and
the durable spool's replays are protected.

## Retry behavior

The emitter retries transient failures (5xx, 429, connection errors) with
exponential backoff: 3 attempts, starting at 1s, capped at 30s. Client errors
(4xx) are not retried.

## Verify the pipeline

```bash
make test-otlp
```

This starts a collector, runs a streaming scan, and verifies events arrive at
the collector.
