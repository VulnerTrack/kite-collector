package envelope

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Detached-signature limits. The signature travels in an HTTP header, so
// its size is bounded by what proxies accept on a single header line
// (nginx defaults to 8 KB); a chain that does not fit is rejected when
// the signer is built rather than on every send.
const (
	maxSignatureHeaderBytes = 8 << 10
	nonceBytes              = 16

	headerIssuedAt = jose.HeaderKey("iat")
	headerNonce    = jose.HeaderKey("jti")
)

// Detached is a signature over a body that travels beside it rather than
// wrapping it (RFC 7515 Appendix F). The body stays byte-for-byte the
// OTLP/JSON a stock receiver expects; the signature proves who produced
// those exact bytes.
type Detached struct {
	// Compact is the detached compact serialization: the protected
	// header and signature separated by two dots, with the payload
	// segment empty ("<protected>..<signature>").
	Compact string
	// SignerKeyID is the "kid": the client-certificate SHA-256
	// fingerprint, or the agent ID for identity-key signatures.
	SignerKeyID string
	// Algorithm is the JWS algorithm (EdDSA, ES256, ...).
	Algorithm string
	// Nonce is the per-signature "jti" a receiver can cache to reject
	// replays.
	Nonce string
	// IssuedAt is the "iat" the signature was produced at.
	IssuedAt time.Time
}

// SignDetached signs payload without encrypting it, returning a signature
// to send alongside the untouched body. Use it when the channel already
// provides confidentiality (mTLS) and what is missing is proof of origin:
// the receiver learns that this agent's certificate signed these exact
// bytes, and that nothing in between altered them.
//
// contentType is stamped as "cty" so the receiver knows what it is
// verifying; empty omits the header. Every signature carries a fresh
// "jti" nonce and an "iat" timestamp so a receiver can reject replayed
// bodies — a signature alone is replayable, since it stays valid for the
// bytes it covers forever.
func (s *Sealer) SignDetached(payload []byte, contentType string) (Detached, error) {
	nonce, issuedAt, opts, err := s.signerOptions(contentType)
	if err != nil {
		return Detached{}, err
	}
	signer, err := jose.NewSigner(s.signingKey(), opts)
	if err != nil {
		return Detached{}, fmt.Errorf("create signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return Detached{}, fmt.Errorf("sign payload: %w", err)
	}
	compact, err := jws.DetachedCompactSerialize()
	if err != nil {
		return Detached{}, fmt.Errorf("serialize detached JWS: %w", err)
	}
	if len(compact) > maxSignatureHeaderBytes {
		return Detached{}, fmt.Errorf(
			"detached signature is %d bytes, over the %d-byte header budget; drop the certificate chain from the signature",
			len(compact), maxSignatureHeaderBytes)
	}
	return Detached{
		Compact:     compact,
		SignerKeyID: s.key.KeyID,
		Algorithm:   string(s.alg),
		Nonce:       nonce,
		IssuedAt:    issuedAt,
	}, nil
}

// VerifyDetached is the receiving half of SignDetached: it checks that
// the signature covers exactly payload and was produced by signerPub.
// Pass a nil signerPub to verify against the leaf of the embedded x5c
// chain — the caller must then validate that chain against its own CA,
// because this only proves the holder of that certificate's private key
// signed the payload, not that the certificate is one you trust.
//
// Freshness is the caller's policy: the returned IssuedAt and Nonce are
// what a receiver checks against its clock skew window and replay cache.
func VerifyDetached(compact string, payload []byte, signerPub crypto.PublicKey) (Opened, error) {
	if compact == "" {
		return Opened{}, fmt.Errorf("verify: signature is empty")
	}
	if len(compact) > maxSignatureHeaderBytes {
		return Opened{}, fmt.Errorf("verify: signature exceeds %d bytes", maxSignatureHeaderBytes)
	}
	jws, err := jose.ParseDetached(compact, payload, signatureAlgorithms)
	if err != nil {
		return Opened{}, fmt.Errorf("verify: parse detached JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return Opened{}, fmt.Errorf("verify: expected exactly one signature, got %d", len(jws.Signatures))
	}

	out, err := openedFromHeader(compact)
	if err != nil {
		return Opened{}, err
	}
	if signerPub == nil {
		if len(out.Certificates) == 0 {
			return Opened{}, fmt.Errorf("verify: no verification key supplied and signature carries no x5c chain")
		}
		signerPub = out.Certificates[0].PublicKey
	}
	if err := jws.DetachedVerify(payload, signerPub); err != nil {
		return Opened{}, fmt.Errorf("verify JWS: %w", err)
	}
	out.Payload = payload
	return out, nil
}

// signerOptions builds the protected header shared by the attached
// (inside-JWE) and detached signing paths, so both stamp the same signer
// identity and the same freshness claims.
func (s *Sealer) signerOptions(contentType string) (nonce string, issuedAt time.Time, opts *jose.SignerOptions, err error) {
	raw := make([]byte, nonceBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", time.Time{}, nil, fmt.Errorf("generate signature nonce: %w", err)
	}
	nonce = base64.RawURLEncoding.EncodeToString(raw)
	issuedAt = time.Now().UTC().Truncate(time.Second)

	opts = (&jose.SignerOptions{}).WithType(typeJWS).
		WithHeader(headerIssuedAt, issuedAt.Unix()).
		WithHeader(headerNonce, nonce)
	if contentType != "" {
		opts = opts.WithContentType(jose.ContentType(contentType))
	}
	if len(s.x5c) > 0 {
		opts = opts.WithHeader(headerCertChain, s.x5c)
	}
	if s.x5t != "" {
		opts = opts.WithHeader(headerSHA256Thumb, s.x5t)
	}
	return nonce, issuedAt, opts, nil
}

func (s *Sealer) signingKey() jose.SigningKey {
	return jose.SigningKey{
		Algorithm: s.alg,
		Key:       jose.JSONWebKey{Key: s.key.Key, KeyID: s.key.KeyID},
	}
}

// openedFromHeader reads the signer-identifying and freshness claims out
// of a compact JWS protected header. Shared by Open and VerifyDetached so
// both surface the same metadata.
func openedFromHeader(compact string) (Opened, error) {
	hdr, err := protectedHeader(compact)
	if err != nil {
		return Opened{}, fmt.Errorf("verify: %w", err)
	}
	out := Opened{
		SignerKeyID: hdr.KeyID,
		ContentType: hdr.ContentType,
		Nonce:       hdr.Nonce,
	}
	if hdr.IssuedAt != 0 {
		out.IssuedAt = time.Unix(hdr.IssuedAt, 0).UTC()
	}
	if len(hdr.CertChain) > 0 {
		out.Certificates, err = parseCertChain(hdr.CertChain)
		if err != nil {
			return Opened{}, fmt.Errorf("verify: x5c: %w", err)
		}
	}
	return out, nil
}
