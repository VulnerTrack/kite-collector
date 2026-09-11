package emitter

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/vulnertrack/kite-collector/internal/envelope"
)

// Wire-level constants for payload protection beyond mTLS (RFC-0072
// §4.8). mTLS authenticates the channel; these authenticate the bytes, so
// a TLS-terminating proxy, a replaying client, or anything else with a
// valid session cannot forge telemetry that verifies as this agent's.
const (
	ContentTypeJSON = "application/json"
	ContentTypeJOSE = "application/jose"

	// HeaderEnvelopeKeyID names the receiver JWK the body was encrypted to
	// (the JWE "kid"), duplicated as a header so a gateway can route to the
	// right decryption key without parsing the JOSE header first. Mirrors
	// SecureEnvelope.key_id in collector.proto.
	HeaderEnvelopeKeyID = "X-Kite-Envelope-Key-Id"
	// HeaderEnvelopeSigner is the JWS "kid": the client-certificate
	// SHA-256 fingerprint or, for identity-key signatures, the agent ID.
	// Present in both protection modes.
	HeaderEnvelopeSigner = "X-Kite-Envelope-Signer"
	// HeaderEnvelopeSignature carries the detached JWS over the request
	// body (RFC 7515 Appendix F): "<protected>..<signature>". The body
	// itself is untouched OTLP/JSON, so a receiver that ignores this
	// header still ingests normally and one that reads it gets
	// authenticity and integrity for the exact bytes it parsed.
	//
	// Deliberately not "X-Kite-Signature": that name is already taken
	// platform-side by the hex HMAC on the package-matrix result webhook,
	// and a header that means two different things is a verification bug
	// waiting to happen.
	HeaderEnvelopeSignature = "X-Kite-Envelope-Signature"
)

// ProtectionMode selects what the agent does to a request body before it
// leaves the process.
type ProtectionMode string

const (
	// ProtectionNone sends plain OTLP/JSON. mTLS is the only protection.
	ProtectionNone ProtectionMode = "none"
	// ProtectionDetached sends plain OTLP/JSON plus a detached signature
	// header. The body stays readable by any OTLP receiver; verification
	// is additive, so signing can be turned on fleet-wide before the
	// receiving side knows how to check it.
	ProtectionDetached ProtectionMode = "detached"
	// ProtectionEnvelope replaces the body with JWE(JWS(body)) sent as
	// application/jose: authenticity, integrity, and confidentiality, at
	// the cost of needing a gateway that unwraps it.
	ProtectionEnvelope ProtectionMode = "envelope"
)

// wirePayload is one HTTP body ready to POST, plus the headers that
// describe it. Built once per batch so retries resend the same bytes —
// and, for signed batches, the same signature over them.
type wirePayload struct {
	body        []byte
	contentType string
	headers     map[string]string
}

// prepareWire applies mode to an OTLP/JSON body. A nil sealer or
// ProtectionNone passes the body through unchanged; the zero
// ProtectionMode means ProtectionEnvelope, matching the historical
// behaviour of "a sealer is configured, so seal".
//
// Failures here — the receiver key could not be fetched, the signing key
// is unusable — are returned unwrapped from the transport so the caller
// can tell them apart from delivery failures. The batch is not sent
// unprotected as a fallback: an operator who asked for signed telemetry
// must never silently get unsigned telemetry.
func prepareWire(ctx context.Context, sealer *envelope.Sealer, mode ProtectionMode, body []byte) (wirePayload, error) {
	plain := wirePayload{body: body, contentType: ContentTypeJSON}
	if sealer == nil {
		return plain, nil
	}

	switch mode {
	case ProtectionNone:
		return plain, nil
	case ProtectionDetached:
		sig, err := sealer.SignDetached(body, ContentTypeJSON)
		if err != nil {
			return wirePayload{}, fmt.Errorf("sign payload: %w", err)
		}
		plain.headers = map[string]string{
			HeaderEnvelopeSignature: sig.Compact,
			HeaderEnvelopeSigner:    sig.SignerKeyID,
		}
		return plain, nil
	case ProtectionEnvelope, "":
		sealed, err := sealer.Seal(ctx, body, ContentTypeJSON)
		if err != nil {
			return wirePayload{}, fmt.Errorf("seal payload: %w", err)
		}
		return wirePayload{
			body:        []byte(sealed.Compact),
			contentType: ContentTypeJOSE,
			headers: map[string]string{
				HeaderEnvelopeKeyID:  sealed.KeyID,
				HeaderEnvelopeSigner: sealed.SignerKeyID,
			},
		}, nil
	default:
		return wirePayload{}, fmt.Errorf("unknown payload protection mode %q", mode)
	}
}

// newRequest builds the POST for this payload.
func (w wirePayload) newRequest(ctx context.Context, endpoint string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(w.body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", w.contentType)
	for k, v := range w.headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	return req, nil
}
