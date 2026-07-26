// Package enrollment implements the agent-side enrollment handshake.
// It submits a token-based request to the PKI server over HTTPS.
package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/identity"
)

const enrollURL = "https://pki.vulnertrack.io/pki/enroll"

// Result holds the outcome of a successful enrollment.
type Result struct {
	Status             string
	CertificateID      string
	JWKSURL            string
	CACertificate      []byte
	ClientCertificate  []byte
	CertificateExpires string
	ClientKey          []byte
}

// httpDoer is the injectable HTTP transport — the real *http.Client in
// production, a stub in tests — so the enrollment error paths are verifiable.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client performs enrollment handshakes with the PKI server.
type Client struct {
	logger *slog.Logger
	http   httpDoer
}

// NewClient creates a new enrollment client.
func NewClient(logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{logger: logger, http: http.DefaultClient}
}

// Enroll submits an enrollment request to the PKI server.
func (c *Client) Enroll(ctx context.Context, agentCode, token string) (*Result, error) {
	csrPEM, keyPEM, signer, err := generateEnrollmentCSR(agentCode)
	if err != nil {
		return nil, fmt.Errorf("generate enrollment key and CSR: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"agent_code":          agentCode,
		"csr_pem":             string(csrPEM),
		"machine_fingerprint": identity.MachineFingerprint(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	c.logger.Info("enrollment HTTP request dispatched to PKI server",
		"code", string(LogCodeEnrollmentStarting),
		"agent_code", agentCode,
		"endpoint", enrollURL)

	doer := c.http
	if doer == nil {
		doer = http.DefaultClient // defensive: a zero-value Client still works
	}
	resp, err := doer.Do(req)
	if err != nil {
		// PKI server unreachable — surface the catalogued KITE-E017 remediation.
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeEnrollmentFailed, err).With("phase", "connect")
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// PKI rejected the request (bad/expired token, wrong agent code, ...).
		return nil, kiteerrors.FromCatalog(kiteerrors.CodeEnrollmentFailed,
			fmt.Errorf("PKI server returned %s: %s", resp.Status, data)).
			With("http_status", resp.StatusCode)
	}

	var result struct {
		Status             string `json:"status"`
		CertificateID      string `json:"certificate_id"`
		JWKSURL            string `json:"jwks_url"`
		CACertificate      string `json:"ca_certificate"`
		ClientCertificate  string `json:"client_certificate"`
		CertificateExpires string `json:"certificate_expires"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if err := validateEnrollmentCertificate(
		agentCode,
		[]byte(result.ClientCertificate),
		[]byte(result.CACertificate),
		signer,
	); err != nil {
		return nil, fmt.Errorf("validate enrollment certificate: %w", err)
	}

	return &Result{
		Status:             result.Status,
		CertificateID:      result.CertificateID,
		JWKSURL:            result.JWKSURL,
		CACertificate:      []byte(result.CACertificate),
		ClientCertificate:  []byte(result.ClientCertificate),
		ClientKey:          keyPEM,
		CertificateExpires: result.CertificateExpires,
	}, nil
}

func generateEnrollmentCSR(agentCode string) ([]byte, []byte, crypto.Signer, error) {
	if agentCode == "" {
		return nil, nil, nil, fmt.Errorf("agent code is required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkixName(agentCode)},
		key,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if len(csrPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, nil, fmt.Errorf("encode enrollment material")
	}
	return csrPEM, keyPEM, key, nil
}

func pkixName(agentCode string) pkix.Name {
	return pkix.Name{CommonName: agentCode}
}

func validateEnrollmentCertificate(
	agentCode string,
	certPEM, caPEM []byte,
	signer crypto.Signer,
) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("response contains no client certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse client certificate: %w", err)
	}
	if cert.Subject.CommonName != agentCode {
		return fmt.Errorf(
			"certificate common name mismatch: got %q, want %q",
			cert.Subject.CommonName,
			agentCode,
		)
	}

	certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	localPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal local public key: %w", err)
	}
	if !bytes.Equal(certPublicKey, localPublicKey) {
		return fmt.Errorf("certificate public key does not match generated private key")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("response contains no valid CA certificate")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("verify client certificate chain: %w", err)
	}
	return nil
}

// StoreCertificates persists the enrollment result to dir.
func StoreCertificates(dir string, result *Result) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return kiteerrors.WrapFileError("create credential dir", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //#nosec G302 -- directory needs execute bit; 0700 is the tightest owner-only dir perm
		return kiteerrors.WrapFileError("secure credential dir", err)
	}

	files := map[string]struct {
		data []byte
		perm os.FileMode
	}{
		"ca.pem":        {data: result.CACertificate, perm: 0o644},
		"agent.pem":     {data: result.ClientCertificate, perm: 0o644},
		"agent-key.pem": {data: result.ClientKey, perm: 0o600},
	}

	for name, f := range files {
		path := filepath.Join(dir, name)
		if err := atomicWrite(path, f.data, f.perm); err != nil {
			return kiteerrors.WrapFileError("write "+name, err)
		}
	}

	return nil
}
