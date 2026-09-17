package recordsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }
func (k keySigner) Fingerprint() string {
	return fingerprintOf(k.priv.Public().(ed25519.PublicKey))
}

func newSigner(t *testing.T) (keySigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return keySigner{priv: priv}, pub
}

func sample() Record {
	return Record{
		TimeUnixNano:         "1758040323000000000",
		ObservedTimeUnixNano: "1758040324000000000",
		SeverityNumber:       9,
		SeverityText:         "info",
		EventName:            "machine.discovered",
		TraceID:              "0192a1b2c3d4e5f60192a1b2c3d4e5f6",
		SpanID:               "0192a1b2c3d4e5f6",
		Body:                 "new machine edge-01",
		Attributes: map[string]string{
			"event.domain":         "security",
			"event.name":           "machine.discovered",
			"security.machine.uid": "01931cb6-b7c4-7c41-a000-0123456789ab",
			"hostname":             "edge-01",
		},
	}
}

func signed(t *testing.T, s Signer, r Record) Record {
	t.Helper()
	sig := Sign(s, r)
	out := r
	out.Attributes = make(map[string]string, len(r.Attributes)+3)
	for k, v := range r.Attributes {
		out.Attributes[k] = v
	}
	for _, kv := range sig.Attributes() {
		out.Attributes[kv[0]] = kv[1]
	}
	return out
}

func TestSignThenVerify(t *testing.T) {
	s, pub := newSigner(t)
	rec := signed(t, s, sample())

	require.NoError(t, Verify(rec, pub))
	assert.Equal(t, AlgorithmEd25519, rec.Attributes[AttrAlgorithm])
	assert.Equal(t, s.Fingerprint(), rec.Attributes[AttrSignerFingerprint])
	assert.Equal(t, Fingerprint(pub), rec.Attributes[AttrSignerFingerprint])
	raw, err := base64.RawURLEncoding.DecodeString(rec.Attributes[AttrSignature])
	require.NoError(t, err)
	assert.Len(t, raw, ed25519.SignatureSize)
}

func TestCanonicalIgnoresAttributeOrderAndSignatureKeys(t *testing.T) {
	a := sample()
	b := sample()
	b.Attributes = map[string]string{}
	// Insert in a different order and add signature keys; both must be
	// invisible to the canonical form.
	for _, k := range []string{"hostname", "security.machine.uid", "event.name", "event.domain"} {
		b.Attributes[k] = a.Attributes[k]
	}
	b.Attributes[AttrSignature] = "junk"
	b.Attributes[AttrSignerFingerprint] = "sha256:junk"
	b.Attributes[AttrAlgorithm] = AlgorithmEd25519

	assert.Equal(t, string(Canonical(a)), string(Canonical(b)))
	assert.Contains(t, string(Canonical(a)), `"attributes":[["event.domain","security"],["event.name","machine.discovered"],["hostname","edge-01"],["security.machine.uid",`)
}

func TestVerifyRejectsTampering(t *testing.T) {
	s, pub := newSigner(t)

	cases := map[string]func(r *Record){
		"body":       func(r *Record) { r.Body = "renamed" },
		"time":       func(r *Record) { r.TimeUnixNano = "1" },
		"observed":   func(r *Record) { r.ObservedTimeUnixNano = "1" },
		"severity":   func(r *Record) { r.SeverityNumber = 17 },
		"event":      func(r *Record) { r.EventName = "machine.changed" },
		"trace":      func(r *Record) { r.TraceID = "" },
		"attr value": func(r *Record) { r.Attributes["hostname"] = "evil-01" },
		"attr added": func(r *Record) { r.Attributes["owner"] = "mallory" },
		"attr gone":  func(r *Record) { delete(r.Attributes, "hostname") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rec := signed(t, s, sample())
			mutate(&rec)
			assert.ErrorIs(t, Verify(rec, pub), ErrInvalidSignature)
		})
	}
}

func TestVerifyDiagnostics(t *testing.T) {
	s, pub := newSigner(t)
	_, otherPub := newSigner(t)

	t.Run("missing", func(t *testing.T) {
		assert.ErrorIs(t, Verify(sample(), pub), ErrMissingSignature)
	})
	t.Run("wrong key", func(t *testing.T) {
		rec := signed(t, s, sample())
		assert.ErrorIs(t, Verify(rec, otherPub), ErrFingerprintMismatch)
	})
	t.Run("wrong key, no fingerprint attribute", func(t *testing.T) {
		rec := signed(t, s, sample())
		delete(rec.Attributes, AttrSignerFingerprint)
		assert.ErrorIs(t, Verify(rec, otherPub), ErrInvalidSignature)
	})
	t.Run("unknown algorithm", func(t *testing.T) {
		rec := signed(t, s, sample())
		rec.Attributes[AttrAlgorithm] = "rsa-pss"
		assert.ErrorIs(t, Verify(rec, pub), ErrUnsupportedAlgorithm)
	})
	t.Run("bad encoding", func(t *testing.T) {
		rec := signed(t, s, sample())
		rec.Attributes[AttrSignature] = "not base64url!!"
		assert.ErrorIs(t, Verify(rec, pub), ErrBadEncoding)
	})
}
