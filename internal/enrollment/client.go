// Package enrollment implements the agent-side enrollment handshake.
// It submits a token-based request to the PKI server over HTTPS.
package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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

// Client performs enrollment handshakes with the PKI server.
type Client struct {
	logger *slog.Logger
}

// NewClient creates a new enrollment client.
func NewClient(logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{logger: logger}
}

// Enroll submits an enrollment request to the PKI server.
func (c *Client) Enroll(ctx context.Context, agentCode, token string) (*Result, error) {
	body, err := json.Marshal(map[string]string{
		"agent_code": agentCode,
		"token":      token,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	c.logger.Info("enrolling with PKI server", "agent_code", agentCode)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("PKI server returned %s: %s", resp.Status, data)
	}

	var result struct {
		Status             string `json:"status"`
		CertificateID      string `json:"certificate_id"`
		JWKSURL            string `json:"jwks_url"`
		CACertificate      string `json:"ca_certificate"`
		ClientCertificate  string `json:"client_certificate"`
		ClientKey          string `json:"client_key"`
		CertificateExpires string `json:"certificate_expires"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &Result{
		Status:            result.Status,
		CertificateID:     result.CertificateID,
		JWKSURL:           result.JWKSURL,
		CACertificate:     []byte(result.CACertificate),
		ClientCertificate: []byte(result.ClientCertificate),
		ClientKey:         []byte(result.ClientKey),
		CertificateExpires: result.CertificateExpires,
	}, nil
}

// StoreCertificates persists the enrollment result to dir.
func StoreCertificates(dir string, result *Result) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}

	files := map[string]struct {
		data []byte
		perm os.FileMode
	}{
		"ca.pem":        {data: result.CACertificate, perm: 0644},
		"agent.pem":     {data: result.ClientCertificate, perm: 0644},
		"agent-key.pem": {data: result.ClientKey, perm: 0600},
	}

	for name, f := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, f.data, f.perm); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return nil
}
