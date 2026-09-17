// Package recordsig signs individual OTLP log records so each one can be
// verified on its own, after any transport envelope has been unwrapped and
// long after the batch it travelled in has been split apart by a pipeline.
//
// The request-level protections in internal/envelope authenticate a whole
// HTTP body; they say nothing once a collector, a queue, or a database has
// re-serialised the records. A per-record signature survives all of that:
// it is carried as three ordinary string attributes on the record itself,
// so any OTLP receiver ingests it unchanged and a verifier only needs the
// record and the signer's public key.
//
// Wire attributes (contract v1.3, additive, present on every log record):
//
//	kite.record.signature          base64url (unpadded) Ed25519 signature
//	kite.record.signer.fingerprint "sha256:<hex>" of the signer's public key,
//	                               the same value identity.Fingerprint returns
//	kite.record.signature.alg      "ed25519"
//
// The signed bytes are Canonical(record): a JSON object with a fixed field
// order, attributes sorted by key, and the three signature attributes
// excluded. Field names mirror OTLP/JSON so a receiver can rebuild the
// canonical form from what it parsed without consulting the agent.
package recordsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

const (
	// AttrSignature carries the record signature.
	AttrSignature = "kite.record.signature"
	// AttrSignerFingerprint names the key that produced it.
	AttrSignerFingerprint = "kite.record.signer.fingerprint"
	// AttrAlgorithm names the signature scheme.
	AttrAlgorithm = "kite.record.signature.alg"

	// AlgorithmEd25519 is the only scheme this package produces.
	AlgorithmEd25519 = "ed25519"
)

// Signer is what the agent identity provides: raw Ed25519 signing plus the
// fingerprint a verifier uses to look the public key up.
type Signer interface {
	Sign(msg []byte) []byte
	Fingerprint() string
}

// Record is the transport-neutral view of one OTLP log record. Attributes
// holds every string attribute except the three signature attributes; Sign
// and Verify ignore those keys if present so callers can pass a record as
// parsed off the wire.
type Record struct {
	Attributes           map[string]string
	TimeUnixNano         string
	ObservedTimeUnixNano string
	SeverityText         string
	EventName            string
	TraceID              string
	SpanID               string
	Body                 string
	SeverityNumber       int
}

// Signature is the trio of attribute values a signed record carries.
type Signature struct {
	Signature         string
	SignerFingerprint string
	Algorithm         string
}

// Attributes returns the signature as attribute key/value pairs in a
// stable order.
func (s Signature) Attributes() [][2]string {
	return [][2]string{
		{AttrSignature, s.Signature},
		{AttrSignerFingerprint, s.SignerFingerprint},
		{AttrAlgorithm, s.Algorithm},
	}
}

var (
	// ErrMissingSignature means the record carries no signature attribute.
	ErrMissingSignature = errors.New("recordsig: record carries no signature")
	// ErrUnsupportedAlgorithm means the record names a scheme this package
	// cannot verify.
	ErrUnsupportedAlgorithm = errors.New("recordsig: unsupported signature algorithm")
	// ErrBadEncoding means the signature attribute is not base64url.
	ErrBadEncoding = errors.New("recordsig: signature is not base64url")
	// ErrInvalidSignature means the signature does not verify against the
	// canonical form of the record with the given key.
	ErrInvalidSignature = errors.New("recordsig: signature does not verify")
	// ErrFingerprintMismatch means the record names a different key than
	// the one offered for verification.
	ErrFingerprintMismatch = errors.New("recordsig: signer fingerprint does not match key")
)

// canonical is the exact shape that gets signed. Field order is the struct
// order; encoding/json never reorders struct fields, and the attributes
// are emitted as a sorted list of pairs rather than a map so the bytes do
// not depend on insertion order.
type canonical struct {
	TimeUnixNano         string      `json:"timeUnixNano"`
	ObservedTimeUnixNano string      `json:"observedTimeUnixNano"`
	SeverityNumber       int         `json:"severityNumber"`
	SeverityText         string      `json:"severityText"`
	EventName            string      `json:"eventName"`
	TraceID              string      `json:"traceId"`
	SpanID               string      `json:"spanId"`
	Body                 string      `json:"body"`
	Attributes           [][2]string `json:"attributes"`
}

// Canonical returns the bytes that Sign signs and Verify checks.
func Canonical(r Record) []byte {
	pairs := make([][2]string, 0, len(r.Attributes))
	for k, v := range r.Attributes {
		if isSignatureAttribute(k) {
			continue
		}
		pairs = append(pairs, [2]string{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	// json.Marshal of a struct with only strings, an int and a slice of
	// string pairs cannot fail.
	out, _ := json.Marshal(canonical{
		TimeUnixNano:         r.TimeUnixNano,
		ObservedTimeUnixNano: r.ObservedTimeUnixNano,
		SeverityNumber:       r.SeverityNumber,
		SeverityText:         r.SeverityText,
		EventName:            r.EventName,
		TraceID:              r.TraceID,
		SpanID:               r.SpanID,
		Body:                 r.Body,
		Attributes:           pairs,
	})
	return out
}

// Sign produces the signature attributes for r with the given signer.
func Sign(s Signer, r Record) Signature {
	return Signature{
		Signature:         base64.RawURLEncoding.EncodeToString(s.Sign(Canonical(r))),
		SignerFingerprint: s.Fingerprint(),
		Algorithm:         AlgorithmEd25519,
	}
}

// Verify checks the signature attributes carried in r.Attributes against
// pub. It does not look the key up: the caller resolves
// kite.record.signer.fingerprint to a public key (an enrolled identity, a
// PKI record) and passes it in; Verify confirms that the fingerprint on the
// record is that key's before checking the signature.
func Verify(r Record, pub ed25519.PublicKey) error {
	sig, ok := r.Attributes[AttrSignature]
	if !ok || sig == "" {
		return ErrMissingSignature
	}
	if alg := r.Attributes[AttrAlgorithm]; alg != "" && alg != AlgorithmEd25519 {
		return ErrUnsupportedAlgorithm
	}
	if fp := r.Attributes[AttrSignerFingerprint]; fp != "" && fp != Fingerprint(pub) {
		return ErrFingerprintMismatch
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrBadEncoding
	}
	if !ed25519.Verify(pub, Canonical(r), raw) {
		return ErrInvalidSignature
	}
	return nil
}

// Fingerprint renders a public key the way the agent identity does, so a
// verifier can compare against kite.record.signer.fingerprint.
func Fingerprint(pub ed25519.PublicKey) string {
	return fingerprintOf(pub)
}

func isSignatureAttribute(key string) bool {
	return key == AttrSignature || key == AttrSignerFingerprint || key == AttrAlgorithm
}
