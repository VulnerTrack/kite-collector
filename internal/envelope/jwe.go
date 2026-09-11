// Package envelope provides JWE encryption/decryption and JWS signing/
// verification for end-to-end payload protection beyond mTLS (RFC-0072
// §4.8). mTLS protects the channel; the envelope protects the payload, so
// a TLS-terminating proxy, a debug log, or a stolen session cannot read
// or forge what the agent sent.
//
// Wire shape: JWE( JWS( payload ) ). The inner JWS is signed with the
// agent's key — the enrolled client certificate's private key when one is
// configured, otherwise the identity.json Ed25519 key — and the outer JWE
// is encrypted to the receiving platform's JWK (ECDH-ES+A256KW, A256GCM).
package envelope

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Key-management and content-encryption algorithms are fixed (RFC-0072
// R13). They are exported so config validation and the receiving side
// can name the same constants instead of re-typing the strings.
const (
	KeyAlgorithm       = jose.ECDH_ES_A256KW
	ContentEncryption  = jose.A256GCM
	headerCertChain    = jose.HeaderKey("x5c")
	headerSHA256Thumb  = jose.HeaderKey("x5t#S256")
	typeJWS            = "JWS"
	typeJWE            = "JWE"
	maxCompactJWEBytes = 64 << 20
)

// signatureAlgorithms lists every JWS algorithm the agent may produce and
// the receiver must accept. Ordering does not matter to go-jose.
var signatureAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA, jose.ES256, jose.ES384, jose.ES512, jose.RS256,
}

// Encrypt encrypts plaintext to the server's public JWK using JWE
// (ECDH-ES+A256KW key agreement, A256GCM content encryption) after
// signing with the agent's key via JWS. The signature algorithm follows
// the key type: Ed25519 → EdDSA, ECDSA P-256/384/521 → ES256/384/512,
// RSA → RS256.
//
// This is the low-level primitive; production callers use Sealer, which
// also stamps kid / x5c headers so the receiver can pick the right
// verification key.
func Encrypt(plaintext []byte, agentKey crypto.Signer, serverJWK jose.JSONWebKey) (string, error) {
	sealer, err := NewSealer(SigningKey{Key: agentKey}, staticProvider{key: serverJWK})
	if err != nil {
		return "", err
	}
	sealed, err := sealer.SealWithKey(plaintext, "", serverJWK)
	if err != nil {
		return "", err
	}
	return sealed.Compact, nil
}

// Decrypt decrypts a JWE compact serialization and verifies the inner
// JWS signature against agentPub. Returns the original plaintext.
func Decrypt(jweCompact string, serverKey jose.JSONWebKey, agentPub crypto.PublicKey) ([]byte, error) {
	opened, err := Open(jweCompact, serverKey, agentPub)
	if err != nil {
		return nil, err
	}
	return opened.Payload, nil
}

// Opened is the result of unwrapping a sealed envelope: the verified
// payload plus the signer-identifying headers the agent stamped on the
// inner JWS, so a receiver that keys verification on them can audit
// which credential produced the payload.
type Opened struct {
	// Payload is the verified plaintext.
	Payload []byte
	// ContentType is the inner JWS "cty" header (e.g. "application/json").
	ContentType string
	// SignerKeyID is the inner JWS "kid" header.
	SignerKeyID string
	// Certificates is the inner JWS "x5c" chain when the agent signed with
	// its client certificate; nil for identity-key signatures.
	Certificates []*x509.Certificate
	// IssuedAt is the "iat" the signature was produced at. A receiver
	// compares it against its own clock to reject stale payloads; zero
	// when the signer stamped no timestamp.
	IssuedAt time.Time
	// Nonce is the per-signature "jti". A receiver that caches nonces for
	// its freshness window rejects replays with it: the signature over a
	// captured body stays valid forever, so nothing but a nonce or a
	// timestamp bound tells a resend apart from the original.
	Nonce string
}

// Open decrypts a JWE compact serialization with serverKey and verifies
// the inner JWS with agentPub. Pass a nil agentPub to verify against the
// leaf of the embedded x5c chain instead — the receiver must then
// validate that chain against its CA itself; Open only proves the
// payload was signed by whoever holds that certificate's private key.
func Open(jweCompact string, serverKey jose.JSONWebKey, agentPub crypto.PublicKey) (Opened, error) {
	if len(jweCompact) > maxCompactJWEBytes {
		return Opened{}, fmt.Errorf("envelope exceeds %d bytes", maxCompactJWEBytes)
	}
	signed, err := decrypt(jweCompact, serverKey)
	if err != nil {
		return Opened{}, fmt.Errorf("decrypt: %w", err)
	}

	jws, err := jose.ParseSigned(string(signed), signatureAlgorithms)
	if err != nil {
		return Opened{}, fmt.Errorf("verify: parse JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return Opened{}, fmt.Errorf("verify: expected exactly one signature, got %d", len(jws.Signatures))
	}

	// go-jose parses x5c into a private field that is only reachable
	// through a chain-verifying accessor, so read the protected header
	// ourselves: the receiver decides how (and against which roots) to
	// validate the chain.
	out, err := openedFromHeader(string(signed))
	if err != nil {
		return Opened{}, err
	}

	if agentPub == nil {
		if len(out.Certificates) == 0 {
			return Opened{}, fmt.Errorf("verify: no verification key supplied and envelope carries no x5c chain")
		}
		agentPub = out.Certificates[0].PublicKey
	}
	out.Payload, err = jws.Verify(agentPub)
	if err != nil {
		return Opened{}, fmt.Errorf("verify JWS: %w", err)
	}
	return out, nil
}

// algorithmFor maps a private key to the JWS algorithm the agent signs
// with. Mirrors enrollment.signMessage's key-type switch so the PKI proof
// path and the telemetry envelope never disagree about a key.
func algorithmFor(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve %q", k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA key too small: %d bits (minimum 2048)", k.N.BitLen())
		}
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}

// jwsProtectedHeader is the subset of the inner JWS protected header the
// receiver needs to identify the signer.
type jwsProtectedHeader struct {
	KeyID       string   `json:"kid"`
	ContentType string   `json:"cty"`
	Nonce       string   `json:"jti"`
	CertChain   []string `json:"x5c"`
	IssuedAt    int64    `json:"iat"`
}

// protectedHeader decodes the first segment of a compact JWS.
func protectedHeader(compact string) (jwsProtectedHeader, error) {
	dot := strings.IndexByte(compact, '.')
	if dot <= 0 {
		return jwsProtectedHeader{}, fmt.Errorf("malformed compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(compact[:dot])
	if err != nil {
		return jwsProtectedHeader{}, fmt.Errorf("decode protected header: %w", err)
	}
	var hdr jwsProtectedHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return jwsProtectedHeader{}, fmt.Errorf("parse protected header: %w", err)
	}
	return hdr, nil
}

func encrypt(plaintext []byte, serverJWK jose.JSONWebKey) (string, error) {
	encrypter, err := jose.NewEncrypter(
		ContentEncryption,
		jose.Recipient{Algorithm: KeyAlgorithm, Key: serverJWK},
		(&jose.EncrypterOptions{}).WithType(typeJWE),
	)
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt payload: %w", err)
	}

	s, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize JWE: %w", err)
	}
	return s, nil
}

func decrypt(jweCompact string, serverKey jose.JSONWebKey) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(jweCompact, []jose.KeyAlgorithm{KeyAlgorithm}, []jose.ContentEncryption{ContentEncryption})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(serverKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}
