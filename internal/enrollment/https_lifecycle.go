package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	heartbeatURL     = "https://pki.vulnertrack.io/pki/agent/heartbeat"
	renewURL         = "https://pki.vulnertrack.io/pki/renew"
	heartbeatEvery   = 5 * time.Minute
	certCheckEvery   = 6 * time.Hour
	maxResponseBytes = 2 << 20
)

type agentMaterial struct {
	certificatePEM []byte
	certificate    *x509.Certificate
	signer         crypto.Signer
	agentCode      string
}

type agentProof struct {
	AgentCode      string `json:"agent_code"`
	CertificatePEM string `json:"certificate_pem"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
}

type agentRenewRequest struct {
	AgentCode                     string `json:"agent_code"`
	CurrentCertificateFingerprint string `json:"current_certificate_fingerprint"`
	CSRPEM                        string `json:"csr_pem"`
	SignedAt                      string `json:"signed_at"`
	ProofSignature                string `json:"proof_signature"`
}

type renewHTTPResponse struct {
	Status             string `json:"status"`
	CACertificate      string `json:"ca_certificate"`
	ClientCertificate  string `json:"client_certificate"`
	CertificateExpires string `json:"certificate_expires"`
}

func canonicalProofMessage(action, agentCode string, timestamp int64, nonce, payloadHash string) []byte {
	return []byte(fmt.Sprintf(
		"kite-pki-v1\n%s\n%s\n%d\n%s\n%s",
		action,
		agentCode,
		timestamp,
		nonce,
		payloadHash,
	))
}

func canonicalRenewalProofMessage(fingerprint, agentCode, signedAt, csrPEM string) []byte {
	csrDigest := sha256.Sum256([]byte(csrPEM))
	return []byte(fmt.Sprintf(
		"vulnertrack-pki-renewal-v1\n%s\n%s\n%s\n%x",
		fingerprint,
		agentCode,
		signedAt,
		csrDigest,
	))
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
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported agent private key format")
}

func loadAgentMaterial(certsDir string) (*agentMaterial, error) {
	certPEM, err := os.ReadFile(filepath.Join(certsDir, "agent.pem"))
	if err != nil {
		return nil, fmt.Errorf("read agent certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, "agent-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("read agent private key: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("agent certificate contains no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse agent certificate: %w", err)
	}
	if cert.Subject.CommonName == "" {
		return nil, fmt.Errorf("agent certificate has no common name")
	}
	signer, err := parsePrivateSigner(keyPEM)
	if err != nil {
		return nil, err
	}
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return nil, fmt.Errorf("agent certificate and private key do not match")
	}
	return &agentMaterial{
		certificatePEM: certPEM,
		certificate:    cert,
		signer:         signer,
		agentCode:      cert.Subject.CommonName,
	}, nil
}

func newNonce() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate proof nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func signProof(material *agentMaterial, action, payloadHash string) (agentProof, error) {
	nonce, err := newNonce()
	if err != nil {
		return agentProof{}, err
	}
	timestamp := time.Now().Unix()
	message := canonicalProofMessage(action, material.agentCode, timestamp, nonce, payloadHash)

	signature, err := signMessage(material.signer, message)
	if err != nil {
		return agentProof{}, err
	}
	return agentProof{
		AgentCode:      material.agentCode,
		CertificatePEM: string(material.certificatePEM),
		Timestamp:      timestamp,
		Nonce:          nonce,
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func signMessage(signer crypto.Signer, message []byte) ([]byte, error) {
	var signature []byte
	var err error
	switch key := signer.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(message)
		signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	case *rsa.PrivateKey:
		digest := sha256.Sum256(message)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, message)
	default:
		err = fmt.Errorf("unsupported agent signing key type %T", signer)
	}
	if err != nil {
		return nil, fmt.Errorf("sign agent proof: %w", err)
	}
	return signature, nil
}

func (c *Client) postAgentRequest(ctx context.Context, endpoint string, payload any, output any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal agent request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create agent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	doer := c.http
	if doer == nil {
		doer = http.DefaultClient
	}
	resp, err := doer.Do(req)
	if err != nil {
		return fmt.Errorf("send agent request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read agent response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PKI returned %s: %s", resp.Status, responseBody)
	}
	if output != nil {
		if err := json.Unmarshal(responseBody, output); err != nil {
			return fmt.Errorf("decode agent response: %w", err)
		}
	}
	return nil
}

// HeartbeatHTTPS proves possession of the enrolled private key over HTTPS/443.
func (c *Client) HeartbeatHTTPS(ctx context.Context, certsDir string) error {
	material, err := loadAgentMaterial(certsDir)
	if err != nil {
		return err
	}
	proof, err := signProof(material, "heartbeat", "")
	if err != nil {
		return err
	}
	return c.postAgentRequest(ctx, heartbeatURL, proof, nil)
}

func generateRenewalCSR(material *agentMaterial) (string, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   material.agentCode,
			Organization: material.certificate.Subject.Organization,
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, material.signer)
	if err != nil {
		return "", fmt.Errorf("create renewal CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// RenewHTTPS renews the certificate over HTTPS and atomically replaces public material.
func (c *Client) RenewHTTPS(ctx context.Context, certsDir string) error {
	material, err := loadAgentMaterial(certsDir)
	if err != nil {
		return err
	}
	csrPEM, err := generateRenewalCSR(material)
	if err != nil {
		return err
	}
	fingerprintDigest := sha256.Sum256(material.certificate.Raw)
	fingerprint := fmt.Sprintf("%x", fingerprintDigest)
	signedAt := time.Now().UTC().Format(time.RFC3339Nano)
	proofMessage := canonicalRenewalProofMessage(
		fingerprint,
		material.agentCode,
		signedAt,
		csrPEM,
	)
	signature, err := signMessage(material.signer, proofMessage)
	if err != nil {
		return err
	}
	var response renewHTTPResponse
	if err := c.postAgentRequest(
		ctx,
		renewURL,
		agentRenewRequest{
			AgentCode:                     material.agentCode,
			CurrentCertificateFingerprint: fingerprint,
			CSRPEM:                        csrPEM,
			SignedAt:                      signedAt,
			ProofSignature:                base64.StdEncoding.EncodeToString(signature),
		},
		&response,
	); err != nil {
		return err
	}
	if response.Status != "renewed" || response.ClientCertificate == "" || response.CACertificate == "" {
		return fmt.Errorf("PKI returned incomplete renewal response")
	}
	if err := validateRenewalResponse(material, response); err != nil {
		return fmt.Errorf("validate renewed certificate: %w", err)
	}
	if err := atomicWrite(filepath.Join(certsDir, "agent.pem"), []byte(response.ClientCertificate), 0o644); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(certsDir, "ca.pem"), []byte(response.CACertificate), 0o644); err != nil {
		return err
	}
	return nil
}

func validateRenewalResponse(
	current *agentMaterial,
	response renewHTTPResponse,
) error {
	if err := validateEnrollmentCertificate(
		current.agentCode,
		[]byte(response.ClientCertificate),
		[]byte(response.CACertificate),
		current.signer,
	); err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(response.ClientCertificate))
	if block == nil {
		return fmt.Errorf("response contains no renewed certificate")
	}
	renewed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse renewed certificate: %w", err)
	}
	if !slices.Equal(
		renewed.Subject.Organization,
		current.certificate.Subject.Organization,
	) {
		return fmt.Errorf("renewed certificate organization does not match current identity")
	}
	if bytes.Equal(renewed.Raw, current.certificate.Raw) {
		return fmt.Errorf("PKI returned the current certificate instead of a replacement")
	}
	if !renewed.NotAfter.After(current.certificate.NotAfter) {
		return fmt.Errorf("renewed certificate does not extend certificate lifetime")
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary credential: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary credential: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary credential: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary credential: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace credential: %w", err)
	}
	return nil
}

// RunHTTPSLifecycle sends heartbeats and renews at two-thirds of certificate life.
func (c *Client) RunHTTPSLifecycle(ctx context.Context, certsDir string) {
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	heartbeatTicker := time.NewTicker(heartbeatEvery)
	defer heartbeatTicker.Stop()
	renewTicker := time.NewTicker(certCheckEvery)
	defer renewTicker.Stop()

	sendHeartbeat := func() {
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := c.HeartbeatHTTPS(requestCtx, certsDir); err != nil {
			logger.Warn("PKI HTTPS heartbeat failed", "error", err)
		}
	}
	checkRenewal := func() {
		material, err := loadAgentMaterial(certsDir)
		if err != nil {
			logger.Warn("PKI certificate check failed", "error", err)
			return
		}
		if !ShouldRenew(material.certificate.NotBefore, material.certificate.NotAfter) {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := c.RenewHTTPS(requestCtx, certsDir); err != nil {
			logger.Error("PKI HTTPS certificate renewal failed", "error", err)
			return
		}
		logger.Info("PKI HTTPS certificate renewal completed")
	}

	sendHeartbeat()
	checkRenewal()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			sendHeartbeat()
		case <-renewTicker.C:
			checkRenewal()
		}
	}
}
