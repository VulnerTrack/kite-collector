package envelope

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// SigningKey is the agent-side credential the inner JWS is signed with.
//
// Two shapes exist. The preferred one is the enrolled client certificate:
// Key is the certificate's private key, Certificates carries the leaf (and
// any intermediates) which is emitted as the JWS x5c header, and KeyID is
// the leaf's SHA-256 fingerprint. The receiver validates the chain against
// its CA and verifies the signature with the leaf — no out-of-band key
// registration needed. The fallback is the identity.json Ed25519 key with
// KeyID set to the agent ID; the receiver must already know that public
// key (it does not travel in the envelope).
type SigningKey struct {
	Key          crypto.Signer
	KeyID        string
	Certificates []*x509.Certificate
}

// LoadSigningKey reads a PEM certificate and private key from disk — the
// same agent.pem / agent-key.pem pair used for mTLS — and returns a
// SigningKey whose kid is the certificate's SHA-256 fingerprint. It
// refuses a cert/key pair whose public keys disagree, so a half-rotated
// certs directory fails loudly at start-up rather than producing
// unverifiable envelopes.
func LoadSigningKey(certFile, keyFile string) (SigningKey, error) {
	certPEM, err := os.ReadFile(certFile) //#nosec G304 -- operator-configured path
	if err != nil {
		return SigningKey{}, fmt.Errorf("read certificate %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile) //#nosec G304 -- operator-configured path
	if err != nil {
		return SigningKey{}, fmt.Errorf("read private key %q: %w", keyFile, err)
	}
	return SigningKeyFromPEM(certPEM, keyPEM)
}

// SigningKeyFromPEM is LoadSigningKey over in-memory PEM blocks.
func SigningKeyFromPEM(certPEM, keyPEM []byte) (SigningKey, error) {
	var chain []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return SigningKey{}, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return SigningKey{}, fmt.Errorf("certificate PEM contains no CERTIFICATE block")
	}

	signer, err := parsePrivateSigner(keyPEM)
	if err != nil {
		return SigningKey{}, err
	}

	certPub, err := x509.MarshalPKIXPublicKey(chain[0].PublicKey)
	if err != nil {
		return SigningKey{}, fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return SigningKey{}, fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certPub, keyPub) {
		return SigningKey{}, fmt.Errorf("certificate and private key do not match")
	}

	return SigningKey{
		Key:          signer,
		KeyID:        CertificateKeyID(chain[0]),
		Certificates: chain,
	}, nil
}

// SigningKeyFromEd25519 wraps the identity.json key. keyID should be the
// agent ID so the receiver can look the public key up by agent.
func SigningKeyFromEd25519(key ed25519.PrivateKey, keyID string) (SigningKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("invalid Ed25519 private key length %d", len(key))
	}
	if keyID == "" {
		return SigningKey{}, fmt.Errorf("key id is required for an identity signing key")
	}
	return SigningKey{Key: key, KeyID: keyID}, nil
}

// CertificateKeyID is the kid an x5c-signed envelope carries: the lowercase
// hex SHA-256 of the leaf's DER, matching the fingerprint the PKI server
// and `kite status` already display.
func CertificateKeyID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func parsePrivateSigner(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("private key contains no PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("PKCS#8 key of type %T cannot sign", key)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

// KeyProvider hands out the receiver's current encryption JWK. JWKSClient
// is the production implementation; tests and single-key deployments can
// use StaticKey.
type KeyProvider interface {
	GetEncryptionKey(ctx context.Context) (jose.JSONWebKey, error)
}

// StaticKey returns a KeyProvider that always yields jwk. Useful when the
// receiver's key is pinned in config or in tests.
func StaticKey(jwk jose.JSONWebKey) KeyProvider { return staticProvider{key: jwk} }

type staticProvider struct{ key jose.JSONWebKey }

func (p staticProvider) GetEncryptionKey(context.Context) (jose.JSONWebKey, error) {
	return p.key, nil
}

// Sealed is one envelope ready for the wire.
type Sealed struct {
	// Compact is the JWE compact serialization (five dot-separated parts).
	Compact string
	// KeyID is the kid of the receiver JWK the envelope was encrypted to.
	// Mirrors SecureEnvelope.key_id in collector.proto.
	KeyID string
	// SignerKeyID is the kid stamped on the inner JWS.
	SignerKeyID string
	// Algorithm is the inner JWS algorithm (EdDSA, ES256, ...).
	Algorithm string
}

// Sealer signs then encrypts payloads. It is safe for concurrent use: the
// signing key is immutable after construction and the KeyProvider handles
// its own locking.
type Sealer struct {
	key       SigningKey
	alg       jose.SignatureAlgorithm
	provider  KeyProvider
	x5c       []string
	x5t       string
	omitChain bool
}

// Option tunes a Sealer at construction.
type Option func(*Sealer)

// WithoutCertificateChain drops the x5c header from signatures, leaving
// only kid and x5t#S256 to identify the signer. Use it when the receiver
// already holds the agent certificates (so the chain is redundant) and
// the few kilobytes it costs per request matter — a detached signature
// travels in an HTTP header, where proxies cap the line length.
func WithoutCertificateChain() Option {
	return func(s *Sealer) { s.omitChain = true }
}

// NewSealer validates the signing key (supported type, kid present) and
// binds it to the receiver-key provider. The result both signs (Sign,
// SignDetached) and encrypts (Seal).
func NewSealer(key SigningKey, provider KeyProvider, opts ...Option) (*Sealer, error) {
	if provider == nil {
		return nil, fmt.Errorf("key provider is nil")
	}
	return newSealer(key, provider, opts)
}

// NewSigner builds a sign-only Sealer: it can produce signatures but not
// envelopes, because no receiver encryption key is configured. This is
// the credential behind authenticity and integrity without
// confidentiality — the shape used when mTLS already protects the
// channel and the payload only needs proof of origin.
func NewSigner(key SigningKey, opts ...Option) (*Sealer, error) {
	return newSealer(key, nil, opts)
}

func newSealer(key SigningKey, provider KeyProvider, opts []Option) (*Sealer, error) {
	if key.Key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	alg, err := algorithmFor(key.Key)
	if err != nil {
		return nil, err
	}
	s := &Sealer{key: key, alg: alg, provider: provider}
	for _, opt := range opts {
		opt(s)
	}
	if len(key.Certificates) > 0 {
		if s.key.KeyID == "" {
			s.key.KeyID = CertificateKeyID(key.Certificates[0])
		}
		if !s.omitChain {
			s.x5c = make([]string, 0, len(key.Certificates))
			for _, c := range key.Certificates {
				s.x5c = append(s.x5c, base64.StdEncoding.EncodeToString(c.Raw))
			}
		}
		sum := sha256.Sum256(key.Certificates[0].Raw)
		s.x5t = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return s, nil
}

// Algorithm reports the inner JWS algorithm this sealer produces.
func (s *Sealer) Algorithm() string { return string(s.alg) }

// SignerKeyID reports the kid stamped on every inner JWS.
func (s *Sealer) SignerKeyID() string { return s.key.KeyID }

// SignsWithCertificate reports whether envelopes carry an x5c chain.
func (s *Sealer) SignsWithCertificate() bool { return len(s.x5c) > 0 }

// Seal fetches the receiver's current encryption key from the provider and
// wraps plaintext. contentType is stamped as the inner JWS "cty" header so
// the receiver knows how to parse the payload after verification (e.g.
// "application/json" for OTLP/JSON); empty omits the header.
func (s *Sealer) Seal(ctx context.Context, plaintext []byte, contentType string) (Sealed, error) {
	if s.provider == nil {
		return Sealed{}, fmt.Errorf("sealer has no receiver key provider: it can sign but not encrypt")
	}
	serverKey, err := s.provider.GetEncryptionKey(ctx)
	if err != nil {
		return Sealed{}, fmt.Errorf("receiver key: %w", err)
	}
	return s.SealWithKey(plaintext, contentType, serverKey)
}

// SealWithKey is Seal with an explicit receiver key, bypassing the provider.
func (s *Sealer) SealWithKey(plaintext []byte, contentType string, serverKey jose.JSONWebKey) (Sealed, error) {
	if serverKey.Key == nil {
		return Sealed{}, fmt.Errorf("receiver key is empty")
	}
	if !serverKey.IsPublic() {
		// Encrypting to a private JWK works but means the agent was handed
		// the receiver's secret — refuse rather than normalise that.
		return Sealed{}, fmt.Errorf("receiver key %q is not a public key", serverKey.KeyID)
	}

	signed, err := s.sign(plaintext, contentType)
	if err != nil {
		return Sealed{}, fmt.Errorf("sign: %w", err)
	}
	encrypted, err := encrypt([]byte(signed), serverKey)
	if err != nil {
		return Sealed{}, fmt.Errorf("encrypt: %w", err)
	}
	return Sealed{
		Compact:     encrypted,
		KeyID:       serverKey.KeyID,
		SignerKeyID: s.key.KeyID,
		Algorithm:   string(s.alg),
	}, nil
}

func (s *Sealer) sign(payload []byte, contentType string) (string, error) {
	_, _, opts, err := s.signerOptions(contentType)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(s.signingKey(), opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign payload: %w", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize JWS: %w", err)
	}
	return compact, nil
}

// parseCertChain decodes a JWS x5c header value (RFC 7515 §4.1.6): base64
// (standard, padded) DER certificates, leaf first.
func parseCertChain(items []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(items))
	for i, s := range items {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
